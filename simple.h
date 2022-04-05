typedef struct process_info {
    int pid;
    char comm[100];
} proc_info;

struct event_t
{
	u32 pid;
	u32 tid;
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	char comm[80];
};

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct bpf_map_def SEC("maps") _name = {                        \
        .type = _type,                                              \
        .key_size = sizeof(_key_type),                              \
        .value_size = sizeof(_value_type),                          \
        .max_entries = _max_entries,                                \
    };

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);

#define READ_KERN_V(ptr)                                   \
	({                                                     \
		typeof(ptr) _val;                                  \
		__builtin_memset((void *)&_val, 0, sizeof(_val));  \
		bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
		_val;                                              \
	})

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events2 SEC(".maps");

long ringbuffer_flags = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";