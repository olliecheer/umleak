#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
    #define print(fmt, args...) bpf_printk(fmt, ##args)
#else
    #define print(fmt, args...)
#endif


struct alloc_t {
    u64 address;
    u32 stack_id;
    pid_t pid;
    u64 size;
    u64 ts_ns;
};

struct stack_alloc_t {
    u32 stack_id;
    // this struct will be store in per-cpu map,
    // possibly negative value if alloc and free are running on different cpu
    s64 total_size;
    s64 count;
};

#define ALLOC_CONTEXT_NR 1024
#define ALLOC_ENTRY_NR 1024000
#define ALLOC_STACK_NR 10240

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, u64); // address
    __uint(max_entries, ALLOC_CONTEXT_NR); // should not be larger than num of threads
} alloc_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // address
    __type(value, struct alloc_t); // allocation info
    __uint(max_entries, ALLOC_ENTRY_NR);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, u32); // stack_id
    __type(value, struct stack_alloc_t); // accumulated alloc info
    __uint(max_entries, ALLOC_STACK_NR); 
} stack_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __uint(max_entries, ALLOC_STACK_NR);
} stack_traces SEC(".maps");

static struct stack_alloc_t *init_stack_allocs_map(u32 stack_id) {
    struct stack_alloc_t init = {};
    init.stack_id = stack_id;
    if(bpf_map_update_elem(&stack_allocs, &stack_id, &init, BPF_NOEXIST) < 0) {
            return NULL;
    }

    return bpf_map_lookup_elem(&stack_allocs, &stack_id);
}

static int enter_alloc(size_t size) {
    if(size == 0 || size > -1) {
        print("%s: invalid alloc size: %llu", __FUNCTION__, size);
        return 0;
    }

    const pid_t pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&alloc_context, &pid, &size, BPF_ANY);
    
    print("%s: alloc %llu bytes", __FUNCTION__, size);
    
    return 0;
}

static int exit_alloc(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    const pid_t pid = bpf_get_current_pid_tgid();
    const u64* size = bpf_map_lookup_elem(&alloc_context, &pid);
    if(!size) {
        print("%s: pid = %lu looks like missed alloc context", __FUNCTION__, pid);
        return 0;
    }

    struct alloc_t info = {};
    info.size = *size;
    if(bpf_map_delete_elem(&alloc_context, &pid) < 0) {
        print("%s: pid = %lu delete from alloc_context failed", __FUNCTION__, pid);
        // unexpected. but no harm to continue
    }

    if(addr == 0) {
        print("%s: pid = %lu alloc failed with address 0", __FUNCTION__, pid);
        return 0;
    }

    info.ts_ns = bpf_ktime_get_ns();
    info.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    if (info.stack_id < 0) {
        print("%s: pid = %lu, addr = %p, size = %llu, stack_id = %lu look up stack id failed",
            __FUNCTION__, pid, addr, info.size, info.stack_id);
        return 1;
    }

    if (bpf_map_update_elem(&allocs, &addr, &info, BPF_NOEXIST) < 0) {
        // print("%s: pid = %lu, addr = %p, size = %llu, stack_id = %lu update map allocs failed",
        //     __FUNCTION__, pid, addr, info.size, info.stack_id);
        return 1;
    }

    struct stack_alloc_t *stack_info = bpf_map_lookup_elem(&stack_allocs, &info.stack_id);
    
    if (!stack_info) {
        stack_info = init_stack_allocs_map(info.stack_id);
        if (!stack_info) {
            print("%s: pid = %lu, stack_id = %lu look up stack_allocs failed after retry !!!",
                __FUNCTION__, pid, info.stack_id);
            return 1;
        }
    }

    // check concurrency here
    stack_info->count++;
    stack_info->total_size += info.size;

    
    print("%s: stack_id = %lu, alloc %llu bytes", __FUNCTION__, info.stack_id, info.size);

    return 0;
}


static int enter_free(void* address) {
    const u64 addr = (u64)address;
    const struct alloc_t *info = bpf_map_lookup_elem(&allocs, &addr);
    if(!info) {
        print("%s: addr = %p missed alloc info", __FUNCTION__, addr);
        return 0;
    }

    u32 stack_id = info->stack_id;
    u64 size = info->size;

    if(bpf_map_delete_elem(&allocs, &addr) < 0) {
        print("%s: addr = %p delete from map allocs failed", __FUNCTION__, addr);
        return 1;
    }

    struct stack_alloc_t *stack_info = bpf_map_lookup_elem(&stack_allocs, &stack_id);

    if(!stack_info) {
        stack_info = init_stack_allocs_map(stack_id);
        if (!stack_info) {
            print("%s: addr = %p, stack_id = %lu look up stack_allocs failed after retry !!!",
                __FUNCTION__, addr, stack_id);
            return 1;
        }
    }
    
    // check concurrency here
    stack_info->count--;
    stack_info->total_size -= size;
    
    return 0;
}


SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) {
    return enter_alloc(size);
}

SEC("uprobe")
int BPF_KRETPROBE(malloc_exit) {
    return exit_alloc(ctx);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t size) {
    return enter_alloc(size);
}

SEC("uprobe")
int BPF_KRETPROBE(calloc_exit) {
    return exit_alloc(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size) {
    enter_free(ptr);
    return enter_alloc(size);
}

SEC("uprobe")
int BPF_KRETPROBE(realloc_exit) {
    return exit_alloc(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void* address, size_t size) {
    return enter_alloc(size);
}

SEC("uprobe")
int BPF_KRETPROBE(mmap_exit) {
    return exit_alloc(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void* address) {
    // bpf_printk("Enter free");
    // return 0;
    return enter_free(address);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void* address) {
    return enter_free(address);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";