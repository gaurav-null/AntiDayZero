/*
 * network_monitor.bpf.c - eBPF network DDoS detection
 * 
 * XDP program for DDoS detection
 * Tracks connection rates via sock_hash maps
 * Monitor SYN flood patterns
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

/* BPF map access flags */
#define BPF_ANY 1
#define BPF_NOEXIST 0
#define BPF_EXIST 1

/* bpf_perf_event_output flags */
#define BPF_F_CURRENT_CPU 0xffffffff

/* XDP actions */
#define XDP_PASS 1
#define XDP_DROP 0
#define XDP_TX 3
#define XDP_REDIRECT 4

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 27
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 10
#define BPF_MAP_TYPE_RINGBUF 29

/* Map attributes */
#define SEC(name) __attribute__((section(name), used))

/* Inline attribute */
#define __always_inline __inline__ __attribute__((always_inline))

/* BPF helpers - declarations we need */
__u64 bpf_get_current_cgroup_id(void);
__u64 bpf_get_current_pid_tgid(void);
__u64 bpf_ktime_get_ns(void);
__u32 bpf_get_prandom_u32(void);
void *bpf_map_lookup_elem(void *map, const void *key);
int bpf_map_update_elem(void *map, const void *key, const void *value, int flags);
int bpf_map_delete_elem(void *map, const void *key);
int bpf_perf_event_output(void *ctx, void *map, __u64 flags, const void *data, __u32 data_size);

/* XDP metadata structure */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 ingress_ifindex;
    __u32 egress_ifindex;
};

/* pt_regs structure for kprobe */
struct pt_regs {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 rdi;
    __u64 rsi;
    __u64 rbp;
    __u64 rbx;
    __u64 rax;
    __u64 rcx;
    __u64 rdx;
};

/* Network monitoring constants */
#define SYN_FLOOD_THRESHOLD 100
#define MAX_TRACKED_CONNECTIONS 65536
#define STATS_WINDOW_SEC 10

/* Network event types */
#define EVENT_TYPE_SYN 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_DISCONNECT 3

/* Bloom filter entry structure for BPF_MAP_TYPE_BLOOM_FILTER */
struct bloom_filter_value {
    __u64 data;
};

/* Control configuration map values */
struct net_control_cfg {
    __u32 window_ms;
    __u32 syn_threshold;
    __u32 connection_rate_threshold;
    __u32 enabled;
    __u64 alert_pipe_fd;
};

/* Per-cgroup network state - tracks connection statistics */
struct net_proc_state {
    __u64 last_ts_ns;
    __u32 total_connections;
    __u32 syn_count;
    __u32 connect_count;
    __u32 disconnect_count;
    __u32 failed_connections;
    __u32 unique_remote_ips;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u32 connection_attempts;
};

/* Per-cgroup network metrics output */
struct net_metrics {
    __u64 timestamp_ns;
    __u32 cgroup_id;
    __u32 total_connections;
    __u32 syn_count;
    __u32 connect_count;
    __u32 disconnect_count;
    __u32 bytes_sent;
    __u32 bytes_recv;
    __u32 unique_remote_ips;
    __u32 connection_attempts;
    __u32 failed_connections;
    __u32 is_ddos;
};

/* Alert event for userspace */
struct ddos_alert {
    __u64 timestamp_ns;
    __u32 cgroup_id;
    __u32 syn_count;
    __u32 connection_rate;
    __u32 is_ddos;
    char comm[16];
};

/* Sock key for tracking connections */
struct sock_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 family;
};

/* Connection state key */
struct conn_key {
    __u32 cgroup_id;
    __u32 saddr;
    __u32 daddr;
};

/* Map definitions using libbpf format */

/* Per-cgroup network state map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct net_proc_state);
} net_state_map SEC(".maps");

/* Per-cgroup network metrics output map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct net_metrics);
} net_metrics_map SEC(".maps");

/* Sock hash for connection tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_CONNECTIONS);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_hash_map SEC(".maps");

/* Control configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_control_cfg);
} net_control_cfg_map SEC(".maps");

/* Ring buffer for alerts */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_alert_rb SEC(".maps");

/* TCP connect tracepoint context structure */
struct trace_event_raw_tcp_connect {
    __u64 __unused;
    __u64 saddr;
    __u64 daddr;
    __u32 sport;
    __u32 dport;
    __u32 uid;
    __u32 ino;
};

/* TCP SYN tracepoint context structure */
struct trace_event_raw_tcp_send_reset {
    __u64 __unused;
    __u32 saddr;
    __u32 daddr;
    __u32 sport;
    __u32 dport;
};

/* Socket close tracepoint context */
struct trace_event_raw_sock_close {
    __u64 __unused;
    __u32 sk;
    __u32 ino;
};

/*
 * XDP program for packet processing
 * Attaches to network interface
 */
SEC("xdp")
int xdp_ddos_monitor(struct xdp_md *ctx)
{
    /* Get current cgroup ID */
    __u32 cgroup_id = bpf_get_current_cgroup_id();
    __u64 ts_ns = bpf_ktime_get_ns();
    
    /* Look up control config */
    __u32 cfg_key = 0;
    struct net_control_cfg *cfg = bpf_map_lookup_elem(&net_control_cfg_map, &cfg_key);
    
    /* If disabled, pass packets through */
    if (!cfg || !cfg->enabled) {
        return XDP_PASS;
    }
    
    /* Get network state for this cgroup */
    struct net_proc_state *state = bpf_map_lookup_elem(&net_state_map, &cgroup_id);
    if (!state) {
        /* Initialize state */
        struct net_proc_state init_state = {};
        init_state.last_ts_ns = ts_ns;
        bpf_map_update_elem(&net_state_map, &cgroup_id, &init_state, BPF_ANY);
        return XDP_PASS;
    }
    
    /* Update state */
    state->total_connections++;
    state->last_ts_ns = ts_ns;
    
    /* Check for DDoS threshold */
    if (state->syn_count > cfg->syn_threshold) {
        /* Generate alert */
        struct ddos_alert alert = {};
        alert.timestamp_ns = ts_ns;
        alert.cgroup_id = cgroup_id;
        alert.syn_count = state->syn_count;
        alert.connection_rate = state->total_connections / STATS_WINDOW_SEC;
        alert.is_ddos = 1;
        
        bpf_perf_event_output(ctx, &net_alert_rb, BPF_F_CURRENT_CPU, &alert, sizeof(alert));
        
        /* Reset counters after alert */
        state->syn_count = 0;
        state->total_connections = 0;
    }
    
    return XDP_PASS;
}

/*
 * Tracepoint: TCP connect
 * Attaches to: tcp:tcp_connect
 */
SEC("tracepoint/tcp/tcp_connect")
int trace_tcp_connect(struct trace_event_raw_tcp_connect *ctx)
{
    __u32 cgroup_id = bpf_get_current_cgroup_id();
    __u64 ts_ns = bpf_ktime_get_ns();
    
    /* Update state */
    struct net_proc_state *state = bpf_map_lookup_elem(&net_state_map, &cgroup_id);
    if (!state) {
        struct net_proc_state init_state = {};
        init_state.last_ts_ns = ts_ns;
        bpf_map_update_elem(&net_state_map, &cgroup_id, &init_state, BPF_ANY);
        state = bpf_map_lookup_elem(&net_state_map, &cgroup_id);
    }
    
    if (state) {
        state->connect_count++;
        state->connection_attempts++;
        state->last_ts_ns = ts_ns;
    }
    
    return 0;
}

/*
 * Tracepoint: TCP SYN (send SYN packet)
 * Attaches to: tcp:tcp_send_reset or via XDP
 */
SEC("kprobe/tcp_send_synack")
int trace_tcp_syn(struct pt_regs *ctx)
{
    __u32 cgroup_id = bpf_get_current_cgroup_id();
    __u64 ts_ns = bpf_ktime_get_ns();
    
    struct net_proc_state *state = bpf_map_lookup_elem(&net_state_map, &cgroup_id);
    if (state) {
        state->syn_count++;
        
        /* Check for SYN flood */
        if (state->syn_count > SYN_FLOOD_THRESHOLD) {
            /* Generate alert */
            struct ddos_alert alert = {};
            alert.timestamp_ns = ts_ns;
            alert.cgroup_id = cgroup_id;
            alert.syn_count = state->syn_count;
            alert.connection_rate = 0;  /* High rate indicated by threshold */
            alert.is_ddos = 1;
            
            bpf_perf_event_output(ctx, &net_alert_rb, BPF_F_CURRENT_CPU, &alert, sizeof(alert));
            
            /* Don't reset - keep counting for rate estimation */
        }
    }
    
    return 0;
}

/*
 * Timer-based metrics export
 * Uses BPF ring buffer for low-latency alert delivery
 */
SEC("timer/usd0")
int export_network_metrics(void *ctx)
{
    __u64 ts_ns = bpf_ktime_get_ns();
    
    /* Iterate over all cgroup states and export metrics */
    /* This is a simplified version - in production, use BPF iterator helpers */
    
    /* For now, we'll export metrics from a single cgroup (root cgroup = 0) */
    __u32 cgroup_id = 0;
    struct net_proc_state *state = bpf_map_lookup_elem(&net_state_map, &cgroup_id);
    
    if (state) {
        struct net_metrics metrics = {};
        metrics.timestamp_ns = ts_ns;
        metrics.cgroup_id = cgroup_id;
        metrics.total_connections = state->total_connections;
        metrics.syn_count = state->syn_count;
        metrics.connect_count = state->connect_count;
        metrics.disconnect_count = state->disconnect_count;
        metrics.bytes_sent = state->bytes_sent;
        metrics.bytes_recv = state->bytes_recv;
        metrics.unique_remote_ips = state->unique_remote_ips;
        metrics.connection_attempts = state->connection_attempts;
        metrics.failed_connections = state->failed_connections;
        metrics.is_ddos = (state->syn_count > SYN_FLOOD_THRESHOLD) ? 1 : 0;
        
        bpf_map_update_elem(&net_metrics_map, &cgroup_id, &metrics, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL-2.0";