/*
 * common.h - Shared definitions for eBPF syscall sketch detector
 * 
 * Minimal definitions for syscall monitoring
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* Define types that we need without pulling in full kernel headers */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/* BPF map definitions */
#define __uint(name, x...) name##_type = x
#define __type(name, x) name##_type = x

/* Helper function prototypes - these are provided by the kernel */
static __always_inline int bpf_get_current_pid_tgid(void);
static __always_inline int bpf_get_current_cgroup_id(void);
static __always_inline int bpf_ktime_get_ns(void);
static __always_inline int bpf_get_prandom_u32(void);
static __always_inline int bpf_map_lookup_elem(const struct bpf_map_def *map, const void *key);
static __always_inline int bpf_map_update_elem(const struct bpf_map_def *map, const void *key, const void *value, int flags);
static __always_inline int bpf_map_delete_elem(const struct bpf_map_def *map, const void *key);
static __always_inline int bpf_perf_event_output(const struct bpf_map_def *map, const void *ctx, u64 arg, const void *data, u32 data_len);
static __always_inline int bpf_ringbuf_reserve(const struct bpf_map_def *map, void *data, u32 size, u32 flags);
static __always_inline int bpf_ringbuf_submit(void *e, u32 flags);
static __always_inline int bpf_ringbuf_discard(void *e, u32 flags);

/* Loop bounds */
#define MAX_SYSCALL_NR 500
#define NGRAM_BUCKETS 64

/* Hash function for n-grams */
static __always_inline u32 hash_bigram(u32 a, u32 b, u32 seed) {
    return (a * 31 + b) ^ seed;
}

static __always_inline u32 hash_trigram(u32 a, u32 b, u32 c) {
    return ((a * 31 + b) * 31 + c) ^ 0xCAFEBABE;
}

/* Bloom filter entry structure */
struct bloom_filter_value {
    u64 data;
};

/* Control configuration map values */
struct control_cfg {
    u32 window_ms;
    u32 sample_rate_mask;
    u32 enabled_syscall_bitmap[8];
    u32 max_sketch_entries;
};

/* Simplified per-process state - no arrays to avoid stack issues */
struct proc_state {
    u64 last_ts_ns;
    u32 prev1;
    u32 prev2;
    u32 total_syscalls;
    u32 novel_ngrams;
    u64 iat_sum_ns;
    u64 iat_sq_sum_ns;
    u64 iat_min_ns;
    u64 iat_max_ns;
};

/* Per-cgroup window sketch output - small enough for stack */
struct window_sketch {
    u64 timestamp_ns;
    u32 cgroup_id;
    u32 comm_hash;
    u32 total_syscalls;
    u32 novel_ngrams;
    u64 bigram_sum;
    u64 trigram_sum;
    u64 iat_sum_ns;
    u64 iat_sq_sum_ns;
    u64 iat_min_ns;
    u64 iat_max_ns;
    u32 is_benign;
};

/* Tracepoint raw_syscalls context structure */
struct trace_event_raw_sys_enter {
    u64 __unused;
    u64 id;
    u64 offset;
    u64 args[6];
};

/* Bloom filter key structure */
struct bloom_key {
    u32 comm_hash;
    u32 ngram_hash;
};

/* Anomaly result for ring buffer */
struct anomaly_event {
    u64 timestamp_ns;
    u32 cgroup_id;
    u32 comm_hash;
    u32 anomaly_score;
    u32 novel_ngrams;
    u32 stage;
    u32 n_features;
    u32 features[0];
};

#endif /* __COMMON_H__ */