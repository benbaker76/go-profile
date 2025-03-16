//go:build ignore

#define __TARGET_ARCH_x86 1

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "maps.h"

#define HASH_STORAGE_SIZE 40960
#define STACK_STORAGE_SIZE 16384
#define MAX_STACK_DEPTH 127

#define CONFIG_DYNAMIC_MEMORY_LAYOUT 1
#define CONFIG_X86_5LEVEL 1
#define PAGE_OFFSET 0xC0000000UL
#define __PAGE_OFFSET_BASE_L5 0xff11000000000000UL
#define __PAGE_OFFSET_BASE_L4 0xffff888000000000UL

static inline __u32 roundup_pow_of_two(__u32 n)
{
    return 1 << (n - 1);
}

typedef __u64 stacktrace_type[MAX_STACK_DEPTH];

struct stack_count_key_t
{
    u32 pid;
    u64 time_stamp;
    u64 kernel_ip;
    s32 user_stack_id;
    s32 kernel_stack_id;
    char name[TASK_COMM_LEN];
};

// Define a struct to hold options
struct options_t
{
    bool use_pidns;
    u64 pidns_dev;
    u64 pidns_ino;
    bool user_stacks_only;
    bool kernel_stacks_only;
    bool use_idle_filter;
    bool use_thread_filter;
    bool use_mntns_filter;
    bool use_cgroup_filter;
    s32 pids[10];
    u32 pids_len;
    s32 tids[10];
    u32 tids_len;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct stack_count_key_t);
    __type(value, __u64);
    __uint(max_entries, HASH_STORAGE_SIZE);
} counts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, __u32);
    __type(value, stacktrace_type);
    __uint(max_entries, STACK_STORAGE_SIZE);
} stack_traces SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024);
} mount_ns_set SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} cgroupset SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct options_t);
    __uint(max_entries, 1);
} options SEC(".maps");

static inline int _cgroup_filter()
{
    u64 cgroupid = bpf_get_current_cgroup_id();

    return bpf_map_lookup_elem(&cgroupset, &cgroupid) == NULL;
}

static inline int _mntns_filter()
{
    struct task_struct *current_task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    unsigned int inum;
    u64 ns_id;

    current_task = (struct task_struct *)bpf_get_current_task();

    if (bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &current_task->nsproxy))
        return 0;

    if (bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns))
        return 0;

    if (bpf_probe_read_kernel(&inum, sizeof(inum), &mnt_ns->ns.inum))
        return 0;

    ns_id = (u64)inum;

    return bpf_map_lookup_elem(&mount_ns_set, &ns_id) == NULL;
}

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
    u64 ts;
    u32 tgid = 0;
    u32 pid = 0;
    u32 options_key = 0;
    struct options_t *opts = NULL;

    opts = bpf_map_lookup_elem(&options, &options_key);

    if (!opts)
    {
        return 0;
    }

    struct bpf_pidns_info ns = {};
    if (opts->use_pidns && !bpf_get_ns_current_pid_tgid(opts->pidns_dev, opts->pidns_ino, &ns, sizeof(struct bpf_pidns_info)))
    {
        tgid = ns.tgid;
        pid = ns.pid;
    }
    else
    {
        u64 id = bpf_get_current_pid_tgid();
        tgid = id >> 32;
        pid = id;
    }

    if (opts->use_idle_filter && pid == 0)
    {
        return 0;
    }

    if (opts->use_thread_filter)
    {
        bool pid_found = false, tid_found = false;

        for (int i = 0; i < opts->pids_len && i < 10; i++)
        {
            if (opts->pids[i] == tgid)
            {
                pid_found = true;
                break;
            }
        }

        for (int i = 0; i < opts->tids_len && i < 10; i++)
        {
            if (opts->tids[i] == pid)
            {
                tid_found = true;
                break;
            }
        }

        if (!pid_found && !tid_found)
        {
            return 0;
        }
    }

    if (opts->use_mntns_filter && _mntns_filter())
    {
        return 0;
    }

    if (opts->use_cgroup_filter && _cgroup_filter())
    {
        return 0;
    }

    // create map event
    struct stack_count_key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.time_stamp = bpf_ktime_get_boot_ns();

    // get stacks
    key.user_stack_id = opts->kernel_stacks_only ? -1 : bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = opts->user_stacks_only ? -1 : bpf_get_stackid(ctx, &stack_traces, 0);

    // bpf_printk("user_stack_id: %d, kernel_stack_id: %d", key.user_stack_id, key.kernel_stack_id);

    if (key.kernel_stack_id >= 0)
    {
        // populate extras to fix the kernel stack
        u64 ip = PT_REGS_IP(&ctx->regs);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif

        if (ip > page_offset)
        {
            key.kernel_ip = ip;
        }
    }

    static const __u64 zero;
    u64 *seen;

    seen = bpf_map_lookup_or_try_init(&counts, &key, &zero);

    if (!seen)
        return 0;

    // Atomically increments the seen counter.
    __sync_fetch_and_add(seen, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";