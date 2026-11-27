#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline
#define UINT(name, value) int (*name)[value]
#define TYPE(name, value) value *name
#define CORE(field) __builtin_preserve_access_index(field)
#define PART_SIZE 4096
#define MAX_PARTS 32

/* The loader verifies the registered process and the virtio character device. */
struct inode {
    unsigned long i_ino;
    unsigned int i_rdev;
} __attribute__((preserve_access_index));

struct file {
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct channel {
    __u64 inode;
    __u32 tgid;
    __u32 device;
};

struct fragment {
    __u32 direction;
    __u32 size;
    __u8 bytes[PART_SIZE];
};

struct {
    UINT(type, BPF_MAP_TYPE_ARRAY);
    UINT(max_entries, 1);
    TYPE(key, __u32);
    TYPE(value, struct channel);
} selected_channel SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_ARRAY);
    UINT(max_entries, 1);
    TYPE(key, __u32);
    TYPE(value, __u64);
} channel_losses SEC(".maps");

struct {
    UINT(type, BPF_MAP_TYPE_RINGBUF);
    UINT(max_entries, 1 << 21);
} channel_fragments SEC(".maps");

static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*current_pid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static long (*copy_user)(void *, __u32, const void *) = (void *)BPF_FUNC_probe_read_user;
static void *(*reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
static void (*discard)(void *, __u64) = (void *)BPF_FUNC_ringbuf_discard;

INLINE void note_loss(__u32 key) {
    __u64 *lost = lookup(&channel_losses, &key);
    if (lost)
        __sync_fetch_and_add(lost, 1);
}

INLINE int collect(__u64 *context, __u32 direction) {
    __s64 size = (__s64)context[4];
    if (size <= 0)
        return 0;

    __u32 key = 0;
    struct channel *configured = lookup(&selected_channel, &key);
    if (!configured || configured->tgid != current_pid() >> 32)
        return 0;

    const struct file *file = (const struct file *)context[0];
    const struct inode *inode = CORE(file->f_inode);
    if (!inode || CORE(inode->i_ino) != configured->inode || CORE(inode->i_rdev) != configured->device)
        return 0;

    if (size > PART_SIZE * MAX_PARTS) {
        note_loss(key);
        return 0;
    }

    const __u8 *buffer = (const __u8 *)context[1];
    for (__u32 i = 0; i < MAX_PARTS; i++) {
        __u32 offset = i * PART_SIZE;
        if (size <= offset)
            break;
        __u32 bytes = size - offset;
        if (bytes > PART_SIZE)
            bytes = PART_SIZE;

        struct fragment *fragment = reserve(&channel_fragments, sizeof(*fragment), 0);
        if (!fragment) {
            note_loss(key);
            return 0;
        }
        fragment->direction = direction;
        fragment->size = bytes;
        if (copy_user(fragment->bytes, bytes, buffer + offset)) {
            discard(fragment, 0);
            note_loss(key);
            return 0;
        }
        submit(fragment, 0);
    }
    return 0;
}

SEC("fexit/vfs_read")
int qga_request(__u64 *context) { return collect(context, 1); }

SEC("fexit/vfs_write")
int qga_response(__u64 *context) { return collect(context, 2); }

char channel_license[] SEC("license") = "Dual MIT/GPL";
