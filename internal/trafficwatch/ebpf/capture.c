/* Counts L3 bytes at TCX hooks. The program never stores packet bodies. */
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline
#define UINT(name, value) int (*name)[value]
#define TYPE(name, value) value *name
#define BUCKET_NS 30000000000ULL
#define BUCKET_COUNT 32
#define PEER_LIMIT 16384

static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*load)(void *, __u32, void *, __u32) = (void *)BPF_FUNC_skb_load_bytes;
static __u64 (*clock_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;

struct address {
    __u8 ip[16];
};

struct peer_key {
    __u64 bucket;
    struct address addr;
    __u8 direction;
    __u8 padding[7];
};

struct totals {
    __u64 bucket;
    __u64 received;
    __u64 sent;
    __u64 unknown;
    __u64 first_ns;
    __u64 last_ns;
    __u64 invalid_ip;
};

struct {
    UINT(type, BPF_MAP_TYPE_ARRAY);
    UINT(max_entries, 1);
    TYPE(key, __u32);
    TYPE(value, __u64);
} offset_ns SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_HASH);
    UINT(max_entries, 16);
    TYPE(key, struct address);
    TYPE(value, __u8);
} local_addrs SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    UINT(max_entries, BUCKET_COUNT);
    TYPE(key, __u32);
    TYPE(value, struct totals);
} bucket_totals SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_LRU_HASH);
    UINT(max_entries, PEER_LIMIT);
    TYPE(key, struct peer_key);
    TYPE(value, __u64);
} peer_bytes SEC(".maps");

INLINE void mapped_v4(struct address *addr, const __u8 *ip) {
    addr->ip[10] = 0xff;
    addr->ip[11] = 0xff;
    __builtin_memcpy(addr->ip + 12, ip, 4);
}

INLINE struct totals *get_totals(__u64 timestamp) {
    __u64 bucket = timestamp / BUCKET_NS;
    __u32 slot = bucket % BUCKET_COUNT;
    struct totals *value = lookup(&bucket_totals, &slot);
    if (!value)
        return 0;
    if (value->bucket != bucket) {
        *value = (struct totals){.bucket = bucket, .first_ns = timestamp};
    }
    value->last_ns = timestamp;
    return value;
}

INLINE int account(struct __sk_buff *skb, __u8 ingress) {
    __u8 ethernet[14];
    if (load(skb, 0, ethernet, sizeof(ethernet)))
        return -1;
    __u32 protocol = ((__u32)ethernet[12] << 8) | ethernet[13];
    __u32 header = sizeof(ethernet);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        __u8 vlan[4];
        if (protocol != 0x8100 && protocol != 0x88a8)
            break;
        if (load(skb, header, vlan, sizeof(vlan)))
            return -1;
        protocol = ((__u32)vlan[2] << 8) | vlan[3];
        header += sizeof(vlan);
    }
    if ((protocol != 0x0800 && protocol != 0x86dd) || skb->len <= header)
        return -1;

    __u32 zero = 0;
    __u64 *offset = lookup(&offset_ns, &zero);
    if (!offset)
        return -1;
    __u64 timestamp = clock_ns() + *offset;
    struct totals *totals = get_totals(timestamp);
    if (!totals)
        return -1;

    struct address source = {}, dest = {};
    __u64 size = skb->len - header;
    if (protocol == 0x0800) {
        __u8 ip[20];
        if (load(skb, header, ip, sizeof(ip)) || ip[0] >> 4 != 4) {
            totals->invalid_ip += size;
            return -1;
        }
        mapped_v4(&source, ip + 12);
        mapped_v4(&dest, ip + 16);
    } else {
        __u8 ip[40];
        if (load(skb, header, ip, sizeof(ip)) || ip[0] >> 4 != 6) {
            totals->invalid_ip += size;
            return -1;
        }
        __builtin_memcpy(&source, ip + 8, 16);
        __builtin_memcpy(&dest, ip + 24, 16);
    }

    int source_local = lookup(&local_addrs, &source) != 0;
    int dest_local = lookup(&local_addrs, &dest) != 0;
    struct peer_key key = {.bucket = totals->bucket};
    // The hook supplies direction even when neither address belongs to the
    // host (forwarding, multicast, new addresses, etc.). The local map is
    // diagnostic only; do not silently remove valid IP from interface totals.
    if ((ingress && (source_local || !dest_local)) ||
        (!ingress && (!source_local || dest_local)))
        totals->unknown += size;
    if (ingress) {
        key.addr = source;
        key.direction = 1;
        totals->received += size;
    } else {
        key.addr = dest;
        key.direction = 2;
        totals->sent += size;
    }

    __u64 *count = lookup(&peer_bytes, &key);
    if (!count) {
        if (update(&peer_bytes, &key, &size, BPF_NOEXIST) == 0)
            return -1;
        count = lookup(&peer_bytes, &key);
    }
    if (count)
        __sync_fetch_and_add(count, size);
    // TCX_NEXT delegates packet handling to the next program or qdisc.
    return -1;
}

SEC("tcx/ingress")
int capture_ingress(struct __sk_buff *skb) { return account(skb, 1); }

SEC("tcx/egress")
int capture_egress(struct __sk_buff *skb) { return account(skb, 0); }

char capture_license[] SEC("license") = "Dual MIT/GPL";
