//+build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "simple.h"

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    proc_info *process;

    // Reserve space on the ringbuffer for the sample
    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    process->pid = tgid;
    bpf_get_current_comm(&process->comm, 100);

    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}

SEC("kprobe/tcp_ack")
int kprobe__tcp_ack(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct inet_sock *inet = (struct inet_sock *)sk;

	struct event_t *task_info;
	task_info = bpf_ringbuf_reserve(&events2, sizeof(struct event_t), 0);
	if (!task_info)
	{
		return 0;
	}

	bpf_get_current_comm(&task_info->comm, 80);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	task_info->pid = pid;
	task_info->tid = pid_tgid;

	task_info->saddr = READ_KERN_V(sk->__sk_common.skc_rcv_saddr);
	task_info->daddr = READ_KERN_V(sk->__sk_common.skc_daddr);
	task_info->sport = __bpf_ntohs(READ_KERN_V(inet->inet_sport));
	task_info->dport = __bpf_htons(READ_KERN_V(sk->__sk_common.skc_dport));

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct inet_sock *inet = (struct inet_sock *)sk;

	struct event_t *task_info;
	task_info = bpf_ringbuf_reserve(&events3, sizeof(struct event_t), 0);
	if (!task_info)
	{
		return 0;
	}
	
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	task_info->pid = pid;
	task_info->tid = pid_tgid;
	task_info->saddr = READ_KERN_V(inet->inet_saddr);
	task_info->daddr = READ_KERN_V(inet->sk.__sk_common.skc_daddr);
	task_info->sport = __bpf_ntohs(READ_KERN_V(inet->inet_sport));
	task_info->dport = __bpf_htons(READ_KERN_V(inet->sk.__sk_common.skc_dport));
	bpf_get_current_comm(&task_info->comm, 80);

	// bpf_printk("trace_tcp >> saddr: %d", task_info->saddr);
	// bpf_printk("trace_tcp >> daddr: %d", task_info->daddr);
	// bpf_printk("trace_tcp >> sport: %d", task_info->sport);
	// bpf_printk("trace_tcp >> dport: %d", task_info->dport);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}