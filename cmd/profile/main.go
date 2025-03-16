// go-profile
// Copyright (C) 2025 Ben Baker
// LICENSE: MIT
// Website: https://github.com/benbaker76/go-profile

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"math"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"debug/dwarf"
	"debug/elf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ianlancetaylor/demangle"

	"github.com/fogleman/gg"

	"github.com/crazy3lf/colorconv"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-15 bpf profile.c -- -I../../headers

const MAX_DEPTH = 127
const EFAULT = 14
const EEXIST = 17
const BPF_F_STACK_BUILD_ID = (1 << 5) // Flag for stack_map, store build_id+offset instead of pointer
const BPF_STACK_BUILD_ID_EMPTY = 0    // can't get stacktrace
const BPF_STACK_BUILD_ID_VALID = 1    // valid build-id,ip
const BPF_STACK_BUILD_ID_IP = 2       // fallback to ip

// Defaults for flame graph options
const FRAME_WIDTH = 1024                                  // Default width for flame graph images
const FRAME_HEIGHT = 800                                  // Default width for flame graph images
const FRAME_FPS = 30                                      // Default frames per second for flame graph images
const DEFAULT_FRAME_PATTERN = "frames/flamegraph%04d.png" // Default file name pattern for frame generation
const DEFAULT_FEED_HOST = "localhost"                     // Default host for the realtime feed
const DEFAULT_FEED_PATH = "/"                             // Default HTTP path for the realtime feed
const DEFAULT_FEED_PORT = 9090                            // Default port for the realtime feed

var EXAMPLES = `examples:
   ./profile                      # profile stack traces at 49 Hertz until Ctrl-C
   ./profile -F 99                # profile stack traces at 99 Hertz
   ./profile -c 1000000           # profile stack traces every 1 in a million events
   ./profile 5                    # profile at 49 Hertz for 5 seconds only
   ./profile -f 5                 # output in folded format for flame graphs
   ./profile -p 185               # only profile process with PID 185
   ./profile -L 185               # only profile thread with TID 185f
   ./profile -U                   # only show user space stacks (no kernel)
   ./profile -K                   # only show kernel space stacks (no user)
   ./profile --cgroupmap mappath  # only trace cgroups in this BPF map
   ./profile --mntnsmap mappath   # only trace mount namespaces in the map
   ./profile -T                   # enable flame graph realtime feed (defaults: 'http://localhost:9090/')
   ./profile -E                   # enable flame graph frame generation (default: 'frames/flamegraph%04d.png')
`

type Options struct {
	UserStackGet     int
	KernelStackGet   int
	Duration         int
	SampleFreq       int
	SamplePeriod     int
	Pids             []int
	Tids             []int
	UserStacksOnly   bool
	KernelStacksOnly bool
	Delimited        bool
	Annotations      bool
	IncludeIdle      bool
	Folded           bool
	HashStorageSize  int
	StackStorageSize int
	Cpu              int
	CgroupMap        string
	MntnsMap         string
	EnableFrameGeneration bool
	EnableRealtimeFeed bool
	FramePattern	 string
	FeedPath         string
	FeedPort         int
}

type MemoryMap struct {
	StartAddress uint64
	EndAddress   uint64
	Permissions  string
	Offset       uint64
	Path         string
}

type TextSize struct {
	Width  float64
	Height float64
}

// Tunables
const (
	fontType    = "Verdana"
	imageWidth  = 1200 // max width, pixels
	frameHeight = 16   // max height is dynamic
	fontSize    = 12   // base text size
	minWidth    = 0.1  // min function width, pixels
)

// Internals
var (
	ypad1            = fontSize * 4            // pad top, include title
	ypad2            = fontSize*2 + 10         // pad bottom, include labels
	xpad             = 10                      // pad left and right
	timeMax          float64                   // maximum time
	depthMax         int                       // maximum depth
	cycleColors      bool              = false // cycle through colors
	cycleIndex       float64           = 0
	eventMap         map[string]*Event = make(map[string]*Event) // map to store events
	tempMap          map[string]*Event = make(map[string]*Event) // temp map to store events
	stackOutput      []string                                    // stack output
	stackOutputMutex sync.RWMutex
)

type Color struct {
	R, G, B uint8
}

// Event struct to store event details
type Event struct {
	FuncName  string
	Index     int
	Depth     int
	StartTime float64
	EndTime   float64
	Color     Color
	Purge     bool
}

type SymbolOption int

const (
	None SymbolOption = iota
	Demangle
	AddVersion
	AddLibrary
)

type KernelSymbol struct {
	StartAddr uint64
	EndAddr   uint64
	Symbol    string
	Name      string
	Modules   []string
	Objects   []string
}

var memoryMapCache = make(map[int][]MemoryMap)
var memoryMapMutex sync.RWMutex
var functionMap = make(map[uint64]string)
var kernelSymbolList []KernelSymbol
var appOptions Options
var startEpoch int64
var startTime int64
var textSizeCache = make(map[string]TextSize)
var imageSequence []image.Image

func parseOptions() Options {
	options := Options{}
	var pidStr, tidStr string

	flag.IntVar(&options.Duration, "", 99999999, "Duration in seconds")
	flag.IntVar(&options.SampleFreq, "F", 49, "Sample frequency in Hz")
	flag.IntVar(&options.SamplePeriod, "c", 10, "Sample period, number of events")
	flag.StringVar(&pidStr, "p", "", "Profile process with one or more comma-separated PIDs only")
	flag.StringVar(&tidStr, "L", "", "Profile thread with one or more comma-separated TIDs only")
	flag.IntVar(&options.HashStorageSize, "hash-storage-size", 40960, "The number of hash keys that can be stored")
	flag.IntVar(&options.StackStorageSize, "stack-storage-size", 16384, "The number of unique stack traces that can be stored and displayed")
	flag.IntVar(&options.Cpu, "C", -1, "CPU number to run profile on")

	flag.BoolVar(&options.UserStacksOnly, "U", false, "Show stacks from user space only (no kernel space stacks)")
	flag.BoolVar(&options.KernelStacksOnly, "K", false, "Show stacks from kernel space only (no user space stacks)")
	flag.BoolVar(&options.Delimited, "d", false, "Insert delimiter between kernel/user stacks")
	flag.BoolVar(&options.Annotations, "a", false, "Add _[k] annotations to kernel frames")
	flag.BoolVar(&options.IncludeIdle, "I", false, "Include CPU idle stacks")
	flag.BoolVar(&options.Folded, "f", false, "Output folded format, one line per stack (for flame graphs)")

	flag.StringVar(&options.CgroupMap, "cgroupmap", "", "Trace cgroups in this BPF map only")
	flag.StringVar(&options.MntnsMap, "mntnsmap", "", "Trace mount namespaces in this BPF map only")

	// Flame graph frame generation options:
	flag.BoolVar(&options.EnableFrameGeneration, "E", false, "Enable flame graph frame generation")
	flag.StringVar(&options.FramePattern, "g", DEFAULT_FRAME_PATTERN, "File name pattern for flame graph frame generation (default: '"+DEFAULT_FRAME_PATTERN+"')")

	// Flame graph realtime feed options:
	flag.BoolVar(&options.EnableRealtimeFeed, "T", false, "Enable flame graph realtime feed")
	flag.StringVar(&options.FeedPath, "P", DEFAULT_FEED_PATH, "HTTP path for flame graph realtime feed (default: '"+DEFAULT_FEED_PATH+"')")
	flag.IntVar(&options.FeedPort, "R", DEFAULT_FEED_PORT, fmt.Sprintf("Port for flame graph realtime feed (default: %d)", DEFAULT_FEED_PORT))

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Profile CPU stack traces at a timed interval\n")
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s\n", EXAMPLES)
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()
	switch len(args) {
	case 0:
		break
	case 1:
		options.Duration, _ = strconv.Atoi(args[0])
	default:
		break
	}

	// Parse PIDs and TIDs
	options.Pids = parseIDs(pidStr)
	options.Tids = parseIDs(tidStr)

	return options
}

// Function to parse comma-separated IDs and populate the array
func parseIDs(idStr string) []int {
	var idArray []int
	idStrings := strings.Split(idStr, ",")
	for _, id := range idStrings {
		parsedID, err := strconv.Atoi(id)
		if err == nil {
			idArray = append(idArray, parsedID)
		}
	}
	return idArray
}

func int8ArrayToString(arr [16]int8) string {
	// Convert the array to a []byte
	var bytes []byte
	for _, char := range arr {
		if char == 0 {
			break
		}
		bytes = append(bytes, byte(char))
	}
	return string(bytes)
}

type StackCount struct {
	key  bpfStackCountKeyT
	seen uint64
}

func stackIdErr(stackID int32) bool {
	// -EFAULT in get_stackid normally means the stack-trace is not available,
	// Such as getting kernel stack trace in userspace code
	return stackID < 0 && stackID != -EFAULT
}

// symbol.bccResolveSymname(module string, symname string, addr uint64, pid int)

type BccStacktraceBuildId struct {
	Status   uint32
	BuildId  [20]byte
	OffsetIp uint64
}

func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

// Function to get the executable file path for a PID
func getExecutablePath(pid int) (string, error) {
	cmd := exec.Command("readlink", fmt.Sprintf("/proc/%d/exe", pid))
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Trim any trailing whitespace or newline characters
	return strings.TrimSpace(out.String()), nil
}

func loadMemoryMaps(pid int) ([]MemoryMap, error) {
	memoryMapMutex.RLock()
	maps, ok := memoryMapCache[pid]
	memoryMapMutex.RUnlock()

	if ok {
		return maps, nil
	}

	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	maps = make([]MemoryMap, 0)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			permissions := fields[1]

			// Check if the permissions contain the 'x' attribute
			if permissions[2] != 'x' {
				continue
			}

			if fields[5] == "[stack]" {
				continue
			}

			if fields[5] == "[vdso]" {
				continue
			}

			if fields[5] == "[heap]" {
				continue
			}

			addressParts := strings.Split(fields[0], "-")
			if len(addressParts) == 2 {
				startAddress, err := strconv.ParseUint(addressParts[0], 16, 64)
				if err != nil {
					return nil, err
				}
				endAddress, err := strconv.ParseUint(addressParts[1], 16, 64)
				if err != nil {
					return nil, err
				}
				offset, err := strconv.ParseUint(fields[2], 16, 64)
				if err != nil {
					return nil, err
				}
				path := fields[len(fields)-1]
				maps = append(maps, MemoryMap{
					StartAddress: startAddress,
					EndAddress:   endAddress,
					Permissions:  permissions,
					Offset:       offset,
					Path:         path,
				})
			}
		}
	}

	memoryMapMutex.Lock()
	memoryMapCache[pid] = maps
	memoryMapMutex.Unlock()

	return maps, nil
}

func loadKernelSymbols() {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		cols := strings.Fields(line)
		if len(cols) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(cols[0], 16, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing address:", err)
		}
		symbol := cols[1]
		name := cols[2]
		ksym := KernelSymbol{StartAddr: addr, EndAddr: addr, Symbol: symbol, Name: name}

		for i := 3; i < len(cols); i++ {
			if strings.HasPrefix(cols[i], "[") && strings.HasSuffix(cols[i], "]") {
				module := strings.TrimPrefix(cols[i], "[")
				module = strings.TrimSuffix(module, "]")
				ksym.Modules = append(ksym.Modules, module)
			} else if strings.HasPrefix(cols[i], "{") && strings.HasSuffix(cols[i], "}") {
				object := strings.TrimPrefix(cols[i], "{")
				object = strings.TrimSuffix(object, "}")
				ksym.Objects = append(ksym.Objects, object)
			}
		}

		kernelSymbolList = append(kernelSymbolList, ksym)
	}

	sort.Slice(kernelSymbolList, func(i, j int) bool {
		return kernelSymbolList[i].StartAddr < kernelSymbolList[j].StartAddr
	})

	for i := 0; i < len(kernelSymbolList)-1; i++ {
		kernelSymbolList[i].EndAddr = kernelSymbolList[i+1].StartAddr
	}

	kernelSymbolList[len(kernelSymbolList)-1].EndAddr = ^uint64(0)
}

func PrintSymbol(sym elf.Symbol) {
	fmt.Printf("\t\tSymbol{\n")
	fmt.Printf("\t\t\tName:         \"%s\",\n", sym.Name)
	fmt.Printf("\t\t\tInfo:         0x%X,\n", sym.Info)
	fmt.Printf("\t\t\tOther:        0x%X,\n", sym.Other)
	fmt.Printf("\t\t\tSection:      0x%X,\n", uint64(sym.Section))
	fmt.Printf("\t\t\tValue:        0x%X,\n", sym.Value)
	fmt.Printf("\t\t\tSize:         0x%X,\n", sym.Size)
	fmt.Printf("\t\t\tVersion:      \"%s\",\n", sym.Version)
	fmt.Printf("\t\t\tLibrary:      \"%s\",\n", sym.Library)
	fmt.Printf("\t\t\tVersionIndex: 0x%X,\n", sym.VersionIndex.Index())
	fmt.Printf("\t\t\tIsHidden:     %v,\n", sym.VersionIndex.IsHidden())

	fmt.Printf("\t\t},\n")
}

func printSymbols(symbolName string, filePath string, symbols []elf.Symbol) {
	fmt.Printf("var %s = map[string][]Symbol{\n", symbolName)
	fmt.Printf("\t\"testdata/%s\": {\n", filePath)

	for _, sym := range symbols {
		PrintSymbol(sym)
	}
}

func getDynamicVersion(sym elf.Symbol, dynVers []elf.DynamicVersion) *elf.DynamicVersion {
	if dynVers == nil {
		return nil
	}

	for _, v := range dynVers {
		if v.Index == uint16(sym.VersionIndex) {
			return &v
		}
	}
	return nil
}

func getDynamicVersionNeed(sym elf.Symbol, dynVerNeeds []elf.DynamicVersionNeed) (*elf.DynamicVersionNeed, *elf.DynamicVersionDep) {
	if dynVerNeeds == nil {
		return nil, nil
	}

	for _, v := range dynVerNeeds {
		for _, n := range v.Needs {
			var index = n.Index & 0x7fff
			if index == uint16(sym.VersionIndex) {
				return &v, &n
			}
		}
	}
	return nil, nil
}

func getSymbolName(sym elf.Symbol, dynVers []elf.DynamicVersion, dynVerNeeds []elf.DynamicVersionNeed, options ...SymbolOption) string {
	demangleSymbol := false
	addVersion := false
	addLibrary := false
	for _, o := range options {
		switch {
		case o == Demangle:
			demangleSymbol = true
		case o == AddVersion:
			addVersion = true
		case o == AddLibrary:
			addLibrary = true
		}
	}

	_, dynVerNeedDep := getDynamicVersionNeed(sym, dynVerNeeds)

	suffix := ""
	if (sym.Info&0xf == 0x2 || sym.Info&0xf == 0x1 && sym.Section == 0 || sym.Section != 0xfff1) && sym.Version != "" {
		if dynVerNeedDep != nil || sym.VersionIndex.IsHidden() {
			suffix = "@" + sym.Version
		} else {
			suffix = "@@" + sym.Version
		}
	}

	symName := sym.Name

	if addLibrary {
		symName += suffix
	}

	if demangleSymbol {
		demangleName, err := demangle.ToString(sym.Name, demangle.NoRust)

		if err == nil {
			symName = demangleName
		}
	}

	if addVersion && dynVerNeedDep != nil {
		if dynVerNeedDep.Index > 1 {
			symName += fmt.Sprintf(" (%d)", dynVerNeedDep.Index)
		}
	}

	return symName
}

func ksymAddr2Index(addr uint64) int {
	index := -1
	for i := 0; i < len(kernelSymbolList); i++ {
		if addr >= kernelSymbolList[i].StartAddr && addr < kernelSymbolList[i].EndAddr {
			index = i
			break
		}
	}
	return index
}

func ksymAddr(addr uint64) string {
	index := ksymAddr2Index(addr)
	if index == -1 {
		return "[unknown]"
	}
	offset := int(addr - kernelSymbolList[index].StartAddr)
	return kernelSymbolList[index].Name + fmt.Sprintf("%x", offset)
}

func getKernelSymbol(addr uint64) string {
	index := ksymAddr2Index(addr)
	if index == -1 {
		return "[unknown]"
	}
	return kernelSymbolList[index].Name
}

func GetKernelSymbol(addr uint64) string {
	symbol := getKernelSymbol(addr)
	if appOptions.Annotations {
		return symbol + "_[k]"
	}
	return symbol
}

func GetUserSymbol(pid int, addr uint64, options ...SymbolOption) string {
	if pid == 0 {
		return getKernelSymbol(addr)
	}
	name, err := getFunctionName(pid, addr, options...)
	if err != nil {
		return "[unknown]"
	}
	return name
}

func getTextSectionDelta(file *elf.File) uint64 {
	var delta = uint64(0)

	section := file.SectionByType(elf.SHT_PROGBITS)

	if section != nil {
		delta = section.Offset
	}

	return delta
}

func loadTextSectionDelta(filePath string) (uint64, error) {
	file, err := elf.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	return getTextSectionDelta(file), nil
}

func alignToPage(baseAddress uint64) uint64 {
	pageSize := uint64(os.Getpagesize())
	if baseAddress%pageSize != 0 {
		baseAddress = ((baseAddress / pageSize) * pageSize) + pageSize
	}
	return baseAddress
}

// Source: https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-83432
// To compute the base address, you determine the memory address associated
// with the lowest p_vaddr value for a PT_LOAD segment. You then obtain the
// base address by truncating the memory address to the nearest multiple of
// the maximum page size. Depending on the kind of file being loaded into
// memory, the memory address might not match the p_vaddr values.
func getBaseAddr(file *elf.File) uint64 {
	var baseAddress uint64 = ^uint64(0)

	for _, p := range file.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		baseAddress = p.Vaddr - p.Off

		break
	}

	return baseAddress & -uint64(os.Getpagesize())
}

func loadBaseAddr(filePath string) (uint64, error) {
	file, err := elf.Open(filePath)
	if err != nil {
		return 0, err
	}

	baseAddress := getBaseAddr(file)

	file.Close()

	return baseAddress, nil
}

// ElfNhdr represents an ELF note header.
type ElfNhdr struct {
	NNamesz uint32
	NDescsz uint32
	NType   uint32
}

// BuildIDInfo represents the build ID information.
type BuildIDInfo struct {
	Nhdr        ElfNhdr
	Name        []byte
	Description string
	BuildID     []byte
}

func parseBuildID(data []byte) (BuildIDInfo, error) {
	var info BuildIDInfo

	// Check if the data is long enough to read the header
	if len(data) < int(binary.Size(info.Nhdr)) {
		return info, fmt.Errorf("invalid build ID data")
	}

	// Read the ELF note header
	headerData := data[:int(binary.Size(info.Nhdr))]
	headerBuf := bytes.NewBuffer(headerData)
	if err := binary.Read(headerBuf, binary.LittleEndian, &info.Nhdr); err != nil {
		return info, err
	}
	data = data[int(binary.Size(info.Nhdr)):]

	// Read the name
	info.Name = data[:info.Nhdr.NNamesz-1]
	data = data[info.Nhdr.NNamesz:]

	if string(info.Name) != "GNU" { // Check the name as a string
		return info, fmt.Errorf("invalid build ID header name")
	}

	// Read the description
	info.Description = string(data[:int(info.Nhdr.NNamesz-4)])
	data = data[int(info.Nhdr.NNamesz-4):]

	// Read the build ID
	info.BuildID = data[:int(info.Nhdr.NDescsz)]

	return info, nil
}

func fileExists(name string) (bool, error) {
	_, err := os.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func parseDwarfInfo(file *elf.File) {
	// Parse the DWARF data.
	dwarfInfo, err := file.DWARF()

	if err != nil {
		fmt.Println("No DWARF data:", err)
	}

	if dwarfInfo == nil {
		// You can now work with the DWARF information.
		// For example, you can iterate through compilation units and retrieve function information.

		// Example: Print function names, offsets, and sizes.
		reader := dwarfInfo.Reader()
		for {
			entry, err := reader.Next()
			if err != nil {
				fmt.Println("Error reading DWARF entry:", err)
				break
			}

			if entry == nil {
				break // End of DWARF data.
			}

			if entry.Tag == dwarf.TagSubprogram {
				nameAttr, nameErr := entry.Val(dwarf.AttrName).(string)
				lowPCAttr, lowPCErr := entry.Val(dwarf.AttrLowpc).(uint64)
				highPCAttr, highPCErr := entry.Val(dwarf.AttrHighpc).(uint64)

				if nameErr != false && lowPCErr != false && highPCErr != false {
					fmt.Printf("Function: %s, lowPC: 0x%x, highPC: 0x%x\n", nameAttr, lowPCAttr, highPCAttr)
				}
			}
		}
	}
}

func getDebugFunctionAddr(path string, mmap MemoryMap, funcName string, options ...SymbolOption) (uint64, uint64, error) {
	file, err := elf.Open(path)

	if err != nil {
		return 0, 0, fmt.Errorf("error opening ELF file: %v", err)
	}

	baseAddress := getBaseAddr(file)

	// Find the ".note.gnu.build-id" section.
	var buildIDSection *elf.Section
	for _, section := range file.Sections {
		if section.Name == ".note.gnu.build-id" {
			buildIDSection = section
			break
		}
	}

	if buildIDSection == nil {
		return 0, 0, fmt.Errorf(".note.gnu.build-id section not found")
	}

	// Read the build ID data from the section.
	buildIDData, err := buildIDSection.Data()
	if err != nil {
		return 0, 0, fmt.Errorf("error reading build ID data: %v", err)
	}

	// Parse the build ID data
	buildIDInfo, err := parseBuildID(buildIDData)
	if err != nil {
		return 0, 0, err
	}

	// Print the build ID (hexadecimal format).
	//fmt.Printf("Build ID: %x\n", buildIDInfo.BuildID)

	// Convert the build ID to a string (use your own conversion logic if needed).
	buildIDStr := fmt.Sprintf("%x", buildIDInfo.BuildID)

	// $ dpkg -L libc6-dbg
	elfFilePath := fmt.Sprintf("/usr/lib/debug/.build-id/%s/%s.debug", buildIDStr[:2], buildIDStr[2:])

	// Open the ELF file.
	f, err := elf.Open(elfFilePath)
	if err != nil {
		return 0, 0, fmt.Errorf("error opening ELF file: %v", err)
	}
	defer f.Close()

	symbols, _ := f.Symbols()

	for _, sym := range symbols {
		symName := getSymbolName(sym, nil, nil, options...)

		if symName == funcName {
			startAddr := mmap.StartAddress - mmap.Offset - baseAddress + sym.Value
			endAddr := startAddr + sym.Size

			return startAddr, endAddr, nil
		}
	}

	return 0, 0, fmt.Errorf("debug info not found")
}

func getDebugFunctionName(path string, mmap MemoryMap, addr uint64, options ...SymbolOption) (string, error) {
	file, err := elf.Open(path)

	if err != nil {
		return "", fmt.Errorf("error opening ELF file: %v", err)
	}

	baseAddress := getBaseAddr(file)

	// Find the ".note.gnu.build-id" section.
	var buildIDSection *elf.Section
	for _, section := range file.Sections {
		if section.Name == ".note.gnu.build-id" {
			buildIDSection = section
			break
		}
	}

	if buildIDSection == nil {
		return "", fmt.Errorf(".note.gnu.build-id section not found")
	}

	// Read the build ID data from the section.
	buildIDData, err := buildIDSection.Data()
	if err != nil {
		return "", fmt.Errorf("error reading build ID data: %v", err)
	}

	// Parse the build ID data
	buildIDInfo, err := parseBuildID(buildIDData)
	if err != nil {
		return "", err
	}

	// Print the build ID (hexadecimal format).
	//fmt.Printf("Build ID: %x\n", buildIDInfo.BuildID)

	// Convert the build ID to a string (use your own conversion logic if needed).
	buildIDStr := fmt.Sprintf("%x", buildIDInfo.BuildID)

	// $ dpkg -L libc6-dbg
	elfFilePath := fmt.Sprintf("/usr/lib/debug/.build-id/%s/%s.debug", buildIDStr[:2], buildIDStr[2:])

	// Open the ELF file.
	f, err := elf.Open(elfFilePath)
	if err != nil {
		return "", fmt.Errorf("error opening ELF file: %v", err)
	}
	defer f.Close()

	symbols, _ := f.Symbols()

	for _, sym := range symbols {
		// Adjust address based on module start
		startAddr := mmap.StartAddress - mmap.Offset - baseAddress + sym.Value
		endAddr := startAddr + sym.Size

		if addr >= startAddr && addr < endAddr {
			symName := getSymbolName(sym, nil, nil, options...)

			return symName, nil
		}
	}

	return "", fmt.Errorf("debug info not found")
}

func canApplyRelocation(sym *elf.Symbol) bool {
	return sym.Section != elf.SHN_UNDEF && sym.Section < elf.SHN_LORESERVE
}

func getRelocationOffsets(f *elf.File) ([]uint64, error) {

	symbols, err := f.DynamicSymbols()

	if err != nil {
		return nil, err
	}

	offsets := make([]uint64, len(symbols))
	section := f.Section(".rela.dyn")

	if section == nil {
		return nil, errors.New("no relocation section found")
	}

	data, _ := section.Data()

	// 24 is the size of Rela64.
	if len(data)%24 != 0 {
		return nil, errors.New("length of relocation section is not a multiple of 24")
	}

	b := bytes.NewReader(data)
	var rela elf.Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		symNo := rela.Info >> 32

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}

		/* sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		} */

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).

		offsets[symNo-1] = uint64(rela.Addend)
	}

	return offsets, nil
}

func getFunctionAddr(pid int, funcName string, options ...SymbolOption) (uint64, uint64, error) {
	memoryMapMutex.RLock()
	memoryMaps, ok := memoryMapCache[pid]
	memoryMapMutex.RUnlock()
	filePath := fmt.Sprintf("/proc/%d/exe", pid)
	fileName, _ := os.Readlink(filePath)
	baseAddress, _ := loadBaseAddr(filePath)

	if !ok {
		var err error
		memoryMaps, err = loadMemoryMaps(pid)
		if err != nil {
			return 0, 0, err
		}
	}

	for _, mmap := range memoryMaps {
		f, err := elf.Open(mmap.Path)

		if err != nil {
			if os.IsNotExist(err) {
				return 0, 0, fmt.Errorf("ELF file not found: %v", err)
			} else if os.IsPermission(err) {
				return 0, 0, fmt.Errorf("permission denied: %v", err)
			} else {
				return 0, 0, fmt.Errorf("error opening ELF file: %v", err)
			}
		}

		defer f.Close()

		var offset uint64 = 0
		//var offsets []uint64 = nil
		if mmap.Path == fileName {
			offset = baseAddress
			//offsets, _ = getRelocationOffsets(f)
		}

		//baseAddress2 := getBaseAddr(f)

		symbols, _ := f.Symbols()

		for _, sym := range symbols {
			symName := getSymbolName(sym, nil, nil, options...)

			if symName == funcName {
				startAddr := mmap.StartAddress - mmap.Offset - offset + sym.Value
				endAddr := startAddr + sym.Size

				return startAddr, endAddr, nil
			}
		}

		dynamicSymbols, _ := f.DynamicSymbols()
		dynamicVersions, _ := f.DynamicVersions()
		dynamicVersionNeeds, _ := f.DynamicVersionNeeds()

		for _, sym := range dynamicSymbols {
			/* var symOffset uint64 = 0

			if offsets != nil {
				symOffset = offsets[index]
			} */

			symName := getSymbolName(sym, dynamicVersions, dynamicVersionNeeds, options...)

			if symName == funcName {
				startAddr := mmap.StartAddress - mmap.Offset - offset + sym.Value
				endAddr := startAddr + sym.Size

				fmt.Printf("                                       mmap.StartAddress=0x%x mmap.Offset=0x%x sym.Value=0x%x sym.Size=0x%x offset=0x%x %s\n", mmap.StartAddress, mmap.Offset, sym.Value, sym.Size, offset, mmap.Path)

				return startAddr, endAddr, nil
			}
		}

		startAddr, endAddr, err := getDebugFunctionAddr(mmap.Path, mmap, funcName, options...)

		if err == nil {
			return startAddr, endAddr, nil
		}
	}

	return 0, 0, fmt.Errorf("function name not found for func %s", funcName)
}

func getFunctionName(pid int, addr uint64, options ...SymbolOption) (string, error) {
	memoryMapMutex.RLock()
	memoryMaps, ok := memoryMapCache[pid]
	memoryMapMutex.RUnlock()
	filePath := fmt.Sprintf("/proc/%d/exe", pid)
	fileName, _ := os.Readlink(filePath)
	baseAddress, _ := loadBaseAddr(filePath)

	if !ok {
		var err error
		memoryMaps, err = loadMemoryMaps(pid)
		if err != nil {
			return "", err
		}
	}

	for _, mmap := range memoryMaps {
		var offset uint64 = 0
		if mmap.Path == fileName {
			offset = baseAddress
		}

		if addr+offset >= mmap.StartAddress && addr+offset < mmap.EndAddress {
			f, err := elf.Open(mmap.Path)

			if err != nil {
				if os.IsNotExist(err) {
					return "", fmt.Errorf("ELF file not found: %v", err)
				} else if os.IsPermission(err) {
					return "", fmt.Errorf("permission denied: %v", err)
				} else {
					return "", fmt.Errorf("error opening ELF file: %v", err)
				}
			}

			defer f.Close()

			symbols, _ := f.Symbols()
			for _, sym := range symbols {
				// Adjust address based on module start
				startAddr := mmap.StartAddress - mmap.Offset - offset + sym.Value
				endAddr := startAddr + sym.Size

				if addr >= startAddr && addr < endAddr {
					symName := getSymbolName(sym, nil, nil, options...)

					return symName, nil
				}
			}

			dynamicSymbols, _ := f.DynamicSymbols()
			dynamicVersions, _ := f.DynamicVersions()
			dynamicVersionNeeds, _ := f.DynamicVersionNeeds()

			for _, sym := range dynamicSymbols {
				// Adjust address based on module start
				startAddr := mmap.StartAddress - mmap.Offset - offset + sym.Value
				endAddr := startAddr + sym.Size

				if addr >= startAddr && addr < endAddr {
					symName := getSymbolName(sym, dynamicVersions, dynamicVersionNeeds, options...)

					return symName, nil
				}
			}

			funcName, err := getDebugFunctionName(mmap.Path, mmap, addr)

			if err == nil {
				return funcName, nil
			}
		}
	}

	return "", fmt.Errorf("function name not found for address 0x%x", addr)
}

func collectSamples(counts *ebpf.Map, stackTraces *ebpf.Map) (stdout []string, stderr []string) {
	if !appOptions.Folded {
		stdout = append(stdout, "")
	}

	needDelimiter := appOptions.Delimited && !(appOptions.UserStacksOnly || appOptions.KernelStacksOnly)
	missingStacks := 0
	hasCollision := false
	var countList []StackCount

	var it = counts.Iterate()

	for {
		var key bpfStackCountKeyT
		var seen uint64

		if !it.Next(&key, &seen) {
			break
		}

		countList = append(countList, StackCount{key, seen})
	}

	sort.Slice(countList, func(i, j int) bool {
		return countList[i].seen > countList[j].seen
	})

	for _, kv := range countList {
		k := kv.key
		v := kv.seen

		if !appOptions.UserStacksOnly && stackIdErr(k.KernelStackId) {
			missingStacks++
			// Hash collision (-EEXIST) suggests that the map size may be too small
			hasCollision = hasCollision || k.KernelStackId == -EEXIST
		}
		if !appOptions.KernelStacksOnly && stackIdErr(k.UserStackId) {
			missingStacks++
			hasCollision = hasCollision || k.UserStackId == -EEXIST
		}

		stackBytes, err := stackTraces.LookupBytes(k.UserStackId)
		if err != nil {
			stderr = append(stderr, fmt.Sprintf("failed to look up user-space stack traces: %v", err))
			continue
		}
		userStack := [MAX_DEPTH]uint64{}
		err = binary.Read(bytes.NewBuffer(stackBytes), binary.LittleEndian, userStack[:])
		if err != nil {
			stderr = append(stderr, fmt.Sprintf("failed to read user-space stack traces: %v", err))
			continue
		}

		stackBytes, err = stackTraces.LookupBytes(k.KernelStackId)
		if err != nil {
			stderr = append(stderr, fmt.Sprintf("failed to look up kernel-space stack traces: %v", err))
			continue
		}
		kernelTmp := [MAX_DEPTH]uint64{}
		_ = binary.Read(bytes.NewBuffer(stackBytes), binary.LittleEndian, kernelTmp[:])
		// Fix kernel stack
		var kernelStack []uint64

		if k.KernelStackId >= 0 {
			// Initialize kernelStack as a slice
			kernelStack = make([]uint64, 0, len(kernelTmp))

			// The earlier IP checking
			if k.KernelIp != 0 {
				kernelStack = append(kernelStack, k.KernelIp)
			}

			// Append the remaining elements from kernelTmp
			kernelStack = append(kernelStack, kernelTmp[:]...)
		}

		if appOptions.Folded {
			// Print folded stack output
			var line []string
			name := int8ArrayToString(k.Name)
			line = append(line, name)
			// If we failed to get the stack is, such as due to no space (-ENOMEM) or
			// hash collision (-EEXIST), we still print a placeholder for consistency
			if !appOptions.KernelStacksOnly {
				if stackIdErr(k.UserStackId) {
					line = append(line, "[Missed User Stack]")
				} else {
					tracedUserStack := tracedAddresses(userStack[:]...)
					userStackSym := make([]string, len(tracedUserStack))
					for i, addr := range tracedUserStack {
						userStackSym[i] = GetUserSymbol(int(k.Pid), addr, Demangle)
					}
					line = append(line, userStackSym...)
				}
			}
			if !appOptions.UserStacksOnly {
				if needDelimiter && k.KernelStackId >= 0 && k.UserStackId >= 0 {
					line = append(line, "-")
				}
				if stackIdErr(k.KernelStackId) {
					line = append(line, "[Missed Kernel Stack]")
				} else {
					tracedKernelStack := tracedAddresses(kernelStack[:]...)
					kernelStackSym := make([]string, len(tracedKernelStack))
					for i, addr := range tracedKernelStack {
						kernelStackSym[i] = GetKernelSymbol(addr)
					}
					line = append(line, kernelStackSym...)
				}
			}
			stdout = append(stdout, fmt.Sprintf("%s %d", strings.Join(line, ";"), v))
		} else {
			// Print default multi-line stack output
			if !appOptions.UserStacksOnly {
				if stackIdErr(k.KernelStackId) {
					stdout = append(stdout, "    [Missed Kernel Stack]")
				} else {
					for _, addr := range tracedAddresses(kernelStack[:]...) {
						stdout = append(stdout, fmt.Sprintf("    [K] %08x %s", addr, GetKernelSymbol(addr)))
					}
				}
			}
			if !appOptions.KernelStacksOnly {
				if needDelimiter && k.UserStackId >= 0 && k.KernelStackId >= 0 {
					stdout = append(stdout, "    --")
				}
				if stackIdErr(k.UserStackId) {
					stdout = append(stdout, "    [Missed User Stack]")
				} else {
					for _, addr := range tracedAddresses(userStack[:]...) {
						stdout = append(stdout, fmt.Sprintf("    [U] %08x %s", addr, GetUserSymbol(int(k.Pid), addr)))
					}
				}
			}
			name := int8ArrayToString(k.Name)
			stdout = append(stdout, fmt.Sprintf("    %-16s %s (%d)", "-", name, k.Pid))
			stdout = append(stdout, fmt.Sprintf("        %d", v))
		}
	}

	// Check missing
	if missingStacks > 0 {
		enomemStr := ""
		if !hasCollision {
			enomemStr = " Consider increasing --stack-storage-size."
		}
		stderr = append(stderr, fmt.Sprintf("WARNING: %d stack traces could not be displayed.%s", missingStacks, enomemStr))
	}

	return stdout, stderr
}

func tracedAddresses(stack ...uint64) []uint64 {
	for i, addr := range stack {
		if addr == 0 {
			return stack[:i]
		}
	}
	return nil
}

func rotateColor(color Color, t float64) Color {
	c1_h, c1_s, c1_v := colorconv.RGBToHSV(color.R, color.G, color.B)
	h := c1_h
	s := c1_s
	v := customModulo(c1_v+t, 1)
	r, g, b, _ := colorconv.HSVToRGB(h, s, v)
	color = Color{r, g, b}
	return color
}

func interpolateColor(color1 Color, color2 Color, ratio float64) Color {
	r := linear(float64(color1.R), float64(color2.R), ratio)
	g := linear(float64(color1.G), float64(color2.G), ratio)
	b := linear(float64(color1.B), float64(color2.B), ratio)
	return Color{uint8(r), uint8(g), uint8(b)}
}

func linear(a float64, b float64, t float64) float64 {
	return a*(1.0-customModulo(t, 1.0)) + b*customModulo(t, 1.0)
}

func customModulo(value, modulus float64) float64 {
	result := math.Mod(value, modulus)
	if result < 0 {
		result += modulus
	}
	return result
}

func getColorRatio(typ string, ratio float64) Color {
	if typ == "hot" {
		var startColor Color = Color{R: 205, G: 0, B: 0}
		var endColor Color = Color{R: 255, G: 230, B: 55}
		return interpolateColor(startColor, endColor, ratio)
	}
	return Color{R: 0, G: 0, B: 0}
}

func getColorRandom(typ string) Color {
	var color Color
	if typ == "hot" {
		color.R = uint8(205 + rand.Intn(50))
		color.G = uint8(rand.Intn(230))
		color.B = uint8(rand.Intn(55))
		return color
	}
	return color
}

// Flow function to update the events map
func flow(index int, lastStack, currentStack string, time float64) {
	lastSplit := strings.Split(lastStack, ";")
	currentSplit := strings.Split(currentStack, ";")

	lastLen := len(lastSplit)
	currentLen := len(currentSplit)
	if currentLen > depthMax {
		depthMax = currentLen
	}

	sameLen := 0
	for ; sameLen < lastLen && sameLen < currentLen; sameLen++ {
		if lastSplit[sameLen] != currentSplit[sameLen] {
			break
		}
	}

	for i := lastLen - 1; i >= sameLen; i-- {
		k := fmt.Sprintf("%s--%d", lastSplit[i], i)
		id := fmt.Sprintf("%s--%0.2f", k, time)

		event := eventMap[id]

		if event == nil {
			event = &Event{Index: index, Depth: i, FuncName: lastSplit[i], StartTime: time, EndTime: time, Color: getColorRandom("hot"), Purge: true}
		}

		tempEvent := tempMap[k]
		if tempEvent != nil {
			if event.Purge {
				event.StartTime = tempEvent.StartTime
				event.Purge = false
			}
			delete(tempMap, k)
		}

		eventMap[id] = event
	}

	for i := sameLen; i < currentLen; i++ {
		k := fmt.Sprintf("%s--%d", currentSplit[i], i)
		tempMap[k] = &Event{StartTime: time}
	}
}

// ParseInput function to parse input data
func parseInput(data []string) {
	for _, node := range eventMap {
		node.Purge = true
	}

	last := ""
	time := 0.0

	for i, line := range data {
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		stack, samples := parts[0], parts[1]
		stack = ";" + stack
		flow(i, last, stack, time)
		s, _ := strconv.ParseFloat(samples, 64)
		time += s
		last = stack
	}
	flow(len(data), last, "", time)
	timeMax = time
	if timeMax == 0 {
		// fmt.Fprintf(os.Stderr, "No stack counts found\n")
		// os.Exit(1)
	}

	for key, node := range eventMap {
		if node.Purge {
			delete(eventMap, key)
		}
	}
}

func measureText(dc *gg.Context, text string) TextSize {
	if size, ok := textSizeCache[text]; ok {
		return size
	}
	width, height := dc.MeasureString(text)
	size := TextSize{Width: width, Height: height}
	textSizeCache[text] = size
	return size
}

func truncateTextToFitWidth(dc *gg.Context, text string, width float64) string {
	ts := measureText(dc, text)
	if ts.Width <= width {
		return text
	}

	truncatedText := ""
	for _, char := range text {
		candidate := truncatedText + string(char) + ".."
		if measureText(dc, candidate).Width > width {
			break
		}
		truncatedText += string(char)
	}

	if len(truncatedText) <= 2 {
		return ""
	}

	return truncatedText + ".."
}

// DrawFrames function to draw frames
func drawFrames(dc *gg.Context) {
	// Convert the map to a slice for sorting
	var eventsSlice []*Event
	for _, node := range eventMap {
		eventsSlice = append(eventsSlice, node)
	}

	// Define a sorting function based on sample size then index
	sort.Slice(eventsSlice, func(i, j int) bool {
		return eventsSlice[i].Index < eventsSlice[j].Index
	})

	for _, node := range eventsSlice {
		funcName := node.FuncName
		depth := node.Depth
		index := node.Index
		startTime := node.StartTime
		endTime := node.EndTime
		color1 := node.Color
		color2 := getColorRatio("hot", float64(index)*(1.0/float64(depth))+cycleIndex)
		color := interpolateColor(color1, color2, 0.5)
		widthPerTime := (float64(dc.Width()) - 2*float64(xpad)) / timeMax

		x1 := float64(xpad) + startTime*widthPerTime
		x2 := float64(xpad) + endTime*widthPerTime
		width := x2 - x1
		if width < minWidth {
			//continue
		}

		if width == 0 {
			continue
		}

		y1 := float64(dc.Height()) - float64(ypad2) - (float64(depth)+1)*frameHeight + 1
		y2 := float64(dc.Height()) - float64(ypad2) - float64(depth)*frameHeight
		height := y2 - y1

		dc.DrawRectangle(x1, y1, width, height)
		dc.SetRGB255(int(color.R), int(color.G), int(color.B))
		dc.FillPreserve()
		dc.Stroke()

		text := funcName

		textSize := measureText(dc, text)

		if textSize.Width+6 > width {
			text = truncateTextToFitWidth(dc, text, width-6)
		}

		dc.SetRGB(0, 0, 0)
		dc.DrawStringWrapped(text, x1+3, y1+(height/2)-(textSize.Height/2), 0, 0, width-6, 1, gg.AlignLeft)
	}
}

func createFlameGraph(lines []string) *gg.Context {
    tempMap = make(map[string]*Event)
    sort.Strings(lines)
    parseInput(lines)

    dc := gg.NewContext(FRAME_WIDTH, FRAME_HEIGHT)
    dc.SetRGB(0, 0, 0)
    dc.Clear()
    dc.SetRGB(1, 1, 1)
    dc.DrawStringAnchored("Flame Graph", float64(dc.Width())/2, fontSize*2, 0.5, 0.5)

    drawFrames(dc)

    return dc
}

func equalLines(a, b []string) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

func serveFlameGraphStream(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	mimeWriter := multipart.NewWriter(w)
	w.Header().Set("Content-Type", fmt.Sprintf("multipart/x-mixed-replace; boundary=%s", mimeWriter.Boundary()))
	partHeader := make(textproto.MIMEHeader)
	partHeader.Add("Content-Type", "image/jpeg")

	flusher, ok := w.(http.Flusher)
	if !ok {
		fmt.Fprintf(os.Stderr, "ResponseWriter does not implement http.Flusher")
		return
	}

	frameInterval := time.Second / FRAME_FPS

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		loopStart := time.Now()

		dc := createFlameGraph(stackOutput)
		frame := dc.Image()

		if appOptions.EnableFrameGeneration {
			if len(stackOutput) > 0 {
				imageSequence = append(imageSequence, frame)
			}
		}

		partWriter, err := mimeWriter.CreatePart(partHeader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create multi-part writer: %v\n", err)
			return
		}

		if err := jpeg.Encode(partWriter, frame, &jpeg.Options{Quality: 75}); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encode: %v\n", err)
			return
		}

		flusher.Flush()

		// Calculate remaining time to achieve the target frame interval.
		elapsedTime := time.Since(loopStart)
		waitTime := frameInterval - elapsedTime
		if waitTime < 0 {
			waitTime = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(waitTime):
		}

		cycleIndex += 0.1
	}
}

// startFlameGraphStream starts the MJPEG server and returns a channel that is closed once the server shuts down.
func startFlameGraphStream(ctx context.Context, path string, port string) <-chan struct{} {
	done := make(chan struct{})
	
	mux := http.NewServeMux()
	mux.HandleFunc(path, serveFlameGraphStream)

	// Create the server with appropriate timeouts.
	srv := &http.Server{
		Addr:         port,
		Handler:      mux,
		//IdleTimeout:  30 * time.Second,
		//ReadTimeout:  30 * time.Second,
		//WriteTimeout: 30 * time.Second,
	}

	// Start the server in its own goroutine.
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	// Wait for cancellation.
	go func() {
		<-ctx.Done()

		// Disable keep-alives to force the closure of lingering connections.
		srv.SetKeepAlivesEnabled(false)

		// Increase the shutdown timeout to 20 seconds.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to shutdown server gracefully: %v\n", err)
			if err := srv.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to force close server: %v\n", err)
			}
		} else {
			fmt.Println("Server shut down gracefully.")
		}
		close(done)
	}()

	return done
}

func parseProfileFile(filePath string, pid int) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return parseProfileLines(string(data), pid)
}

func parseProfileLines(data string, pid int) error {
	matchCount := 0
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 && (parts[0] == "K:" || parts[0] == "U:") {
			addrStr := parts[1]
			symName := strings.Join(parts[2:], " ")
			addr, err := strconv.ParseUint(addrStr, 0, 64)
			if err != nil {
				fmt.Println("Error parsing hex address:", err)
				return err
			}
			if parts[0] == "K:" {
				name := GetKernelSymbol(addr)

				if name != symName {
					fmt.Printf("Mismatch! Address: 0x%016x, SymName: %s\n", addr, name)
					fmt.Printf("                                       SymName: %s\n", symName)
				} else {
					matchCount++
				}
			} else if parts[0] == "U:" {
				name := GetUserSymbol(int(pid), addr, Demangle)

				if name != symName {
					fmt.Printf("Mismatch! Address: 0x%016x, SymName: %s\n", addr, name)
					fmt.Printf("                                       SymName: %s\n", symName)
					startAddr, endAddr, err := getFunctionAddr(pid, symName, Demangle)
					if err == nil {
						var offset uint64
						var sign string
						if addr < startAddr {
							offset = startAddr - addr
							sign = "-"
						} else if addr >= endAddr {
							offset = addr - endAddr
							sign = "+"
						}
						fmt.Printf("                                       startAddr=0x%08x endAddr=0x%08x offset=%s0x%x\n", startAddr, endAddr, sign, offset)
					}
				} else {
					matchCount++
				}
			}
		}
	}

	fmt.Printf("matchCount=%d\n", matchCount)

	return nil
}

func main() {
	appOptions = parseOptions()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Error %s\n", err)
		os.Exit(1)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Loading objects: %v\n", err)
		os.Exit(1)
	}
	defer objs.Close()

	var bpfOptions bpfOptionsT

	// pid-namespace translation
	var devinfo unix.Stat_t
	err := unix.Stat("/proc/self/ns/pid", &devinfo)
	if err == nil {
		bpfOptions.UsePidns = true
		bpfOptions.PidnsDev = devinfo.Dev
		bpfOptions.PidnsIno = devinfo.Ino
	}

	bpfOptions.PidsLen = uint32(len(appOptions.Pids))
	bpfOptions.TidsLen = uint32(len(appOptions.Tids))

	bpfOptions.UseIdleFilter = !appOptions.IncludeIdle
	bpfOptions.UseThreadFilter = bpfOptions.PidsLen > 0 || bpfOptions.TidsLen > 0

	for i := 0; i < len(appOptions.Pids) && i < 10; i++ {
		bpfOptions.Pids[i] = int32(appOptions.Pids[i])
	}

	for i := 0; i < len(appOptions.Pids) && i < 10; i++ {
		bpfOptions.Tids[i] = int32(appOptions.Pids[i])
	}

	bpfOptions.UserStacksOnly = appOptions.UserStacksOnly
	bpfOptions.KernelStacksOnly = appOptions.KernelStacksOnly

	if appOptions.CgroupMap != "" {
		bpfOptions.UseCgroupFilter = true

		err = objs.bpfMaps.Cgroupset.Pin(appOptions.CgroupMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Cgroupset.Pin: %v\n", err)
			os.Exit(1)
		}
	}

	if appOptions.MntnsMap != "" {
		bpfOptions.UseMntnsFilter = true

		err = objs.bpfMaps.MountNsSet.Pin(appOptions.MntnsMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error MountNsSet.Pin: %v\n", err)
			os.Exit(1)
		}
	}

	err = objs.bpfMaps.Options.Put(int32(0), bpfOptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Options.Put: %v\n", err)
		os.Exit(1)
	}

	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		if appOptions.Cpu != -1 && appOptions.Cpu != cpu {
			continue
		}

		fd, err := unix.PerfEventOpen(
			&unix.PerfEventAttr{
				// PERF_TYPE_SOFTWARE event type indicates that
				// we are measuring software events provided by the kernel.
				Type: unix.PERF_TYPE_SOFTWARE,
				// Config is a Type-specific configuration.
				// PERF_COUNT_SW_CPU_CLOCK reports the CPU clock, a high-resolution per-CPU timer.
				Config: unix.PERF_COUNT_SW_CPU_CLOCK,
				// Size of attribute structure for forward/backward compatibility.
				Size: uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
				// Sample could mean sampling period (expressed as the number of occurrences of an event)
				// or frequency (the average rate of samples per second).
				// See https://perf.wiki.kernel.org/index.php/Tutorial#Period_and_rate.
				// In order to use frequency PerfBitFreq flag is set below.
				// The kernel will adjust the sampling period to try and achieve the desired rate.
				Sample: uint64(appOptions.SampleFreq),
				Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
			},
			-1,
			cpu,
			// groupFd argument allows event groups to be created.
			// A single event on its own is created with groupFd = -1
			// and is considered to be a group with only 1 member.
			-1,
			// PERF_FLAG_FD_CLOEXEC flag enables the close-on-exec flag for the created
			// event file descriptor, so that the file descriptor is
			// automatically closed on execve(2).
			unix.PERF_FLAG_FD_CLOEXEC,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open the perf event: %v\n", err)
			return
		}
		defer func(fd int) {
			if err = unix.Close(fd); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to close the perf event: %v\n", err)
			}
		}(fd)

		// Attach the BPF program to the perf event.
		err = unix.IoctlSetInt(
			fd,
			unix.PERF_EVENT_IOC_SET_BPF,
			// This BPF program file descriptor was created by a previous bpf(2) system call.
			objs.bpfPrograms.DoPerfEvent.FD(),
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach BPF program to perf event: %v\n", err)
			return
		}

		// PERF_EVENT_IOC_ENABLE enables the individual event or
		// event group specified by the file descriptor argument.
		err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to enable the perf event: %v\n", err)
			return
		}
		// PERF_EVENT_IOC_DISABLE disables the individual counter or
		// event group specified by the file descriptor argument.
		defer func(fd int) {
			err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to disable the perf event: %v\n", err)
			}
		}(fd)
	}

	// Create a cancellable context that will be used for all cancellation events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for OS signals and cancel the context when one is received.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGTSTP)
	go func() {
		<-sig
		cancel()
	}()

	// Get the start time.
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 4, uintptr(unsafe.Pointer(&ts)), 0)
	startEpoch = int64(time.Now().Unix())
	startTime = ts.Nano()

	profilingDuration := time.Duration(appOptions.Duration) * time.Second

	loadKernelSymbols()

	// If realtime feed or frame generation is enabled, enforce folded output.
	if appOptions.EnableRealtimeFeed || appOptions.EnableFrameGeneration {
		appOptions.Folded = true
	}

	var serverDone <-chan struct{}

	// Start the realtime flame graph stream, if enabled.
	if appOptions.EnableRealtimeFeed {
		fmt.Printf("Starting flame graph stream on 'http://%s:%d%s'.\n", DEFAULT_FEED_HOST, appOptions.FeedPort, appOptions.FeedPath)
		serverDone = startFlameGraphStream(ctx, appOptions.FeedPath, fmt.Sprintf(":%d", appOptions.FeedPort))
	}

	// Optionally, print a message if frame generation is enabled.
	if appOptions.EnableFrameGeneration {
		fmt.Printf("Generating flame graph frames.\n")
	}

	// Ticker to update stack data based on sample frequency.
	updateDataTicker := time.NewTicker(time.Second / time.Duration(appOptions.SampleFreq))
	defer updateDataTicker.Stop()

	var lastFrameTime time.Time

	// Start a goroutine that updates stack data and, if needed, generates frames.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-updateDataTicker.C:
				// Update stack data.
				stackOutput, _ = collectSamples(objs.bpfMaps.Counts, objs.bpfMaps.StackTraces)

				// If realtime feed is off and frame generation is on, generate frames on a regular interval.
				if !appOptions.EnableRealtimeFeed && appOptions.EnableFrameGeneration {
					now := time.Now()
					if now.Sub(lastFrameTime) >= time.Second/FRAME_FPS {
						if len(stackOutput) > 0 {
							dc := createFlameGraph(stackOutput)
							imageSequence = append(imageSequence, dc.Image())
							cycleIndex += 0.1
						}
						lastFrameTime = now
					}
				}
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "Waiting for stack traces for %v...\n", profilingDuration)

	// Wait until profiling duration has elapsed or a signal is received.
	select {
	case <-time.After(profilingDuration):
		cancel()
	case <-sig:
		cancel()
	}

	// If the realtime feed server was started, wait for it to shut down.
	if serverDone != nil {
		<-serverDone
	}

	// At this point, no new frames will be added.
	// If neither realtime feed nor frame generation is enabled, just output the raw samples.
	if !appOptions.EnableRealtimeFeed && !appOptions.EnableFrameGeneration {
		stdout, stderr := collectSamples(objs.bpfMaps.Counts, objs.bpfMaps.StackTraces)
		fmt.Fprintln(os.Stdout, strings.Join(stdout, "\n"))
		fmt.Fprintln(os.Stderr, strings.Join(stderr, "\n"))
	}

	// If frame generation is enabled, write the global image sequence to disk.
	if appOptions.EnableFrameGeneration {
		for index, img := range imageSequence {
			gg.SavePNG(fmt.Sprintf("frames/flamegraph%04d.png", index), img)
		}
	}
}
