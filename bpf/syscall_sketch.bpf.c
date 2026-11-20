/*
 * syscall_sketch.bpf.c - eBPF syscall anomaly detector
 * 
 * Attaches to tracepoint/raw_syscalls/sys_enter
 * Computes n-gram sketches per cgroup for anomaly detection
 */

/* Avoid linux/types.h dependency - define types locally first */
#define __u8  unsigned char
#define __u16 unsigned short
#define __u32 unsigned int
#define __u64 unsigned long long
#define __s8  signed char
#define __s16 signed short
#define __s32 signed int
#define __s64 signed long long

/* BPF map definitions macros - match libbpf convention */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 27
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_BLOOM_FILTER 28
#define BPF_MAP_TYPE_RINGBUF 29
#define BPF_MAP_TYPE_PERCPU_ARRAY 10

/* Map attributes */
#define SEC(name) __attribute__((section(name), used))

/* BPF helpers - declarations we need */
__u64 bpf_get_current_pid_tgid(void);
__u32 bpf_get_current_cgroup_id(void);
__u64 bpf_ktime_get_ns(void);
__u32 bpf_get_prandom_u32(void);
void *bpf_map_lookup_elem(void *map, const void *key);
int bpf_map_update_elem(void *map, const void *key, const void *value, int flags);

#define __always_inline __inline__ __attribute__((always_inline))
#define BPF_ANY 1
#define BPF_NOEXIST 0

/* N-gram bucket count - reduced for smaller memory footprint */
#define NGRAM_BUCKETS 64

/* Hash functions */
static __always_inline __u32 hash_bigram(__u32 a, __u32 b, __u32 seed) {
    return (a * 31 + b) ^ seed;
}

static __always_inline __u32 hash_trigram(__u32 a, __u32 b, __u32 c) {
    return ((a * 31 + b) * 31 + c) ^ 0xCAFEBABE;
}

/* Bloom filter entry structure for BPF_MAP_TYPE_BLOOM_FILTER */
struct bloom_filter_value {
    __u64 data;
};

/* Control configuration map values */
struct control_cfg {
    __u32 window_ms;
    __u32 sample_rate_mask;
    __u32 enabled_syscall_bitmap[8];
    __u32 max_sketch_entries;
};

/* Simplified per-process state - no arrays to avoid stack issues */
struct proc_state {
    __u64 last_ts_ns;
    __u32 prev1;
    __u32 prev2;
    __u32 total_syscalls;
    __u32 novel_ngrams;
    __u64 iat_sum_ns;
    __u64 iat_sq_sum_ns;
    __u64 iat_min_ns;
    __u64 iat_max_ns;
};

/* Per-cgroup window sketch output - small enough for stack */
struct window_sketch {
    __u64 timestamp_ns;
    __u32 cgroup_id;
    __u32 comm_hash;
    __u32 total_syscalls;
    __u32 novel_ngrams;
    __u64 bigram_sum;
    __u64 trigram_sum;
    __u64 iat_sum_ns;
    __u64 iat_sq_sum_ns;
    __u64 iat_min_ns;
    __u64 iat_max_ns;
    __u32 is_benign;
};

/* Tracepoint raw_syscalls context structure */
struct trace_event_raw_sys_enter {
    __u64 __unused;
    __u64 id;
    __u64 offset;
    __u64 args[6];
};

/* Bloom filter key structure */
struct bloom_key {
    __u32 comm_hash;
    __u32 ngram_hash;
};

/* Map definitions using libbpf format */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct proc_state);
} proc_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct window_sketch);
} cgroup_sketch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 8192);
    __type(key, struct bloom_key);
    __type(value, struct bloom_filter_value);
} bloom_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct control_cfg);
} control_cfg_map SEC(".maps");

/* Tracepoint handler for raw_syscalls/sys_enter */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscalls(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 syscall_nr = ctx->id;

    /* Bounds check - filter out most syscalls to reduce noise */
    if (syscall_nr >= 500) {
        return 0;
    }

    /* Lookup or create per-process state */
    struct proc_state *state = bpf_map_lookup_elem(&proc_state_map, &pid_tgid);
    if (!state) {
        /* Initialize state to zero - use a single struct with all zeros */
        struct proc_state init_state;
        init_state.last_ts_ns = bpf_ktime_get_ns();
        init_state.prev1 = 0;
        init_state.prev2 = 0;
        init_state.total_syscalls = 0;
        init_state.novel_ngrams = 0;
        init_state.iat_sum_ns = 0;
        init_state.iat_sq_sum_ns = 0;
        init_state.iat_min_ns = 0;
        init_state.iat_max_ns = 0;
        bpf_map_update_elem(&proc_state_map, &pid_tgid, &init_state, BPF_ANY);
        goto update_stats;
    }

    /* Update total syscall count */
    __sync_fetch_and_add(&state->total_syscalls, 1);

    /* Get current timestamp for IAT calculation */
    __u64 ts_ns = bpf_ktime_get_ns();

    /* Update inter-arrival time stats */
    __u64 iat = ts_ns > state->last_ts_ns ? ts_ns - state->last_ts_ns : 0;
    if (iat > 0 && state->total_syscalls > 1) {
        state->iat_sum_ns += iat;
        state->iat_sq_sum_ns += iat * iat;
        if (state->iat_min_ns == 0 || iat < state->iat_min_ns) {
            state->iat_min_ns = iat;
        }
        if (iat > state->iat_max_ns) {
            state->iat_max_ns = iat;
        }
    }
    state->last_ts_ns = ts_ns;

    /* Compute and hash bigram/trigram */
    __u32 bigram_hash = hash_bigram(state->prev1, syscall_nr, 0xDEADBEEF);
    __u32 trigram_hash = hash_trigram(state->prev2, state->prev1, syscall_nr);

    /* Update bucket indices (modulo by power of 2) */
    __u32 bigram_bucket = bigram_hash & (NGRAM_BUCKETS - 1);
    __u32 trigram_bucket = trigram_hash & (NGRAM_BUCKETS - 1);
    
    /* These variables are marked as used to avoid compiler warnings */
    (void)bigram_bucket;
    (void)trigram_bucket;

    /* Bloom filter novelty check (after warmup) */

    /* Bloom filter novelty check (after warmup) */
    if (state->total_syscalls > 100) {
        struct bloom_key bf_key = { .comm_hash = 0, .ngram_hash = bigram_hash };
        
        if (!bpf_map_lookup_elem(&bloom_filter_map, &bf_key)) {
            __sync_fetch_and_add(&state->novel_ngrams, 1);
        }
        
        bf_key.ngram_hash = trigram_hash;
        if (!bpf_map_lookup_elem(&bloom_filter_map, &bf_key)) {
            __sync_fetch_and_add(&state->novel_ngrams, 1);
        }
    }

    /* Shift syscall history */
    state->prev2 = state->prev1;
    state->prev1 = syscall_nr;

update_stats:
    return 0;
}

char LICENSE[] SEC("license") = "GPL-2.0";
