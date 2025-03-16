//go:build linux

package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type SymbolInfo struct {
	Num   int
	Value string
	Size  string
	Type  string
	Bind  string
	Vis   string
	Ndx   string
	Name  string
}

func getLibraryFolder() (string, error) {
	basePath := "/usr/lib"
	var archFolder string

	switch runtime.GOARCH {
	case "amd64":
		archFolder = "x86_64-linux-gnu"
	case "arm64":
		archFolder = "aarch64-linux-gnu"
	case "386":
		archFolder = "i386-linux-gnu"
	case "arm":
		archFolder = "arm-linux-gnueabihf"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	folderPath := filepath.Join(basePath, archFolder)

	// Check if the folder exists
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		return "", fmt.Errorf("folder does not exist: %s", folderPath)
	}

	return folderPath, nil
}

func TestSymbols(t *testing.T) {
	folderPath, err := getLibraryFolder()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	searchPattern := ".so"

	files, err := searchFiles(folderPath, searchPattern)
	if err != nil {
		t.Errorf("Error %v", err)
		return
	}

	t.Logf("Found %d files", len(files))

	for _, file := range files {

		//t.Logf("Processing %s", file)

		symbols, err := parseSymbols(file)
		if err != nil {
			continue
		}

		f, err := elf.Open(file)

		if err != nil {
			continue
		}

		var checkSymbols = make(map[string][]elf.Symbol)

		checkSymbols[".dynsym"], _ = f.DynamicSymbols()
		checkSymbols[".symtab"], _ = f.Symbols()

		dynVers, _ := f.DynamicVersions()
		dynVerNeeds, _ := f.DynamicVersionNeeds()

		mismatch := false

		for tableName, tableSymbols := range symbols {
			if len(tableSymbols) != len(checkSymbols[tableName]) {
				t.Errorf("expected %d got %d\n", len(tableSymbols), len(checkSymbols[tableName]))
			}

			for index, symbol := range tableSymbols {
				symbolCheck := checkSymbols[tableName][index]

				if strings.HasPrefix(symbol.Name, ".") {
					continue
				}

				// Output for the test
				//PrintSymbol(symbolCheck)
				//continue

				value := fmt.Sprintf("%016x", symbolCheck.Value)
				size := fmt.Sprintf("%d", symbolCheck.Size)
				if strings.HasPrefix(symbol.Size, "0x") {
					size = fmt.Sprintf("0x%x", symbolCheck.Size)
				}
				type_ := parseType(int(symbolCheck.Info & 0xf))
				bind := parseBind(int(symbolCheck.Info >> 4))
				vis := parseVisibility(int(symbolCheck.Other))
				ndx := parseNdx(int(symbolCheck.Section))
				name := getSymbolName(symbolCheck, dynVers, dynVerNeeds, AddLibrary, AddVersion)

				if value != symbol.Value {
					t.Errorf("expected %v got %v\n", symbol.Value, value)
					mismatch = true
				}
				if size != symbol.Size {
					t.Errorf("expected %x got %x\n", symbol.Size, size)
					mismatch = true
				}
				if type_ != symbol.Type {
					t.Errorf("expected %v got %v\n", symbol.Type, type_)
					mismatch = true
				}
				if bind != symbol.Bind {
					t.Errorf("expected %x got %v\n", symbol.Bind, bind)
					mismatch = true
				}
				if vis != symbol.Vis {
					t.Errorf("expected %v got %v\n", symbol.Vis, vis)
					mismatch = true
				}
				if ndx != symbol.Ndx {
					t.Errorf("expected %v got %v\n", symbol.Ndx, ndx)
					mismatch = true
				}
				if name != symbol.Name {
					t.Errorf("expected %v got %v\n", symbol.Name, name)
					mismatch = true
				}
			}
		}

		if mismatch {
			t.Errorf("mismatch in %s\n", file)
		}
	}
}

func searchFiles(folderPath, searchPattern string) ([]string, error) {
	var files []string

	file, err := os.Open(folderPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfos, err := file.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() && strings.Contains(fileInfo.Name(), searchPattern) {
			files = append(files, folderPath+"/"+fileInfo.Name())
		}
	}

	return files, nil
}

func parseSymbols(filePath string) (map[string][]SymbolInfo, error) {
	cmd := exec.Command("readelf", "-sW", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	//fmt.Printf("%s\n", output)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	symbols := make(map[string][]SymbolInfo)
	var tableName string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Symbol table") {
			startPos := strings.Index(line, "'")
			endPos := strings.LastIndex(line, "'")
			tableName = line[startPos+1 : endPos]
			continue
		}

		if strings.HasPrefix(line, "   Num:") {
			scanner.Scan()
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		name := ""

		symbol := SymbolInfo{
			Num:   len(symbols[tableName]),
			Value: fields[1],
			Size:  fields[2],
			Type:  fields[3],
			Bind:  fields[4],
			Vis:   fields[5],
			Ndx:   fields[6],
			Name:  name,
		}

		if len(fields) == 8 {
			symbol.Name = fields[7]
		} else if len(fields) == 9 {
			if fields[6] == "[VARIANT_PCS]" {
				symbol.Ndx = fields[7]
				symbol.Name = fields[8]
			} else {
				symbol.Name = fields[7] + " " + fields[8]
			}
		}

		symbols[tableName] = append(symbols[tableName], symbol)
	}

	return symbols, nil
}

func parseType(typeInt int) string {
	typeTable := map[int]string{
		0:  "NOTYPE",
		1:  "OBJECT",
		2:  "FUNC",
		3:  "SECTION",
		4:  "FILE",
		5:  "COMMON",
		6:  "TLS",
		10: "IFUNC",
		13: "LOPROC",
		15: "HIPROC",
	}

	return typeTable[typeInt]
}

func parseBind(bindInt int) string {
	bindTable := map[int]string{
		0:  "LOCAL",
		1:  "GLOBAL",
		2:  "WEAK",
		10: "UNIQUE",
		11: "UNIQUE",
		12: "UNIQUE",
	}

	return bindTable[bindInt]
}

func parseVisibility(visInt int) string {
	visTable := map[int]string{
		0: "DEFAULT",
		1: "INTERNAL",
		2: "HIDDEN",
		3: "PROTECTED",
	}

	return visTable[visInt&0x7f]
}

func parseNdx(ndxInt int) string {
	ndxTable := map[int]string{
		0:      "UND",
		0xff00: "BEFORE",
		0xff01: "AFTER",
		0xff1f: "HIPROC",
		0xfff1: "ABS",
		0xfff2: "COMMON",
		0xffff: "HIRESERVE",
	}

	if val, ok := ndxTable[ndxInt]; ok {
		return val
	}

	return strconv.FormatInt(int64(ndxInt), 10)
}
