from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from hexdump import hexdump

from logger import logger

import sys


def hook_uds_msg(pids: list, debug=False):
    def print_pkg(cpu, data, size):
        event = b["unix_msg_events"].event(data)
        pth = ''
        for i in range(1, len(event.pth)):
            if chr(event.pth[i]) == '\0':
                break
            pth += chr(event.pth[i])
        if chr(event.pth[0]) == '\0':
            pth = '@' + pth
        else:
            pth = chr(event.pth[0]) + pth
        logger.info(f"LEN: {event.len}\tPATH: {pth}")
        logger.info(f"PID: {event.src_pid}->{event.dst_pid}\tUID: {event.uid}\tGID: {event.gid}")
        pkt = b''
        for i in range(0, event.len):
            pkt += chr(event.pkt[i]).encode('latin-1')
        # print(pkt)
        for line in hexdump(pkt, result='return').split('\n'):
            logger.success(line)

    for pid in pids:
        assert isinstance(pid, int), "malformed pid"

    bpf_text = """
#include <uapi/linux/un.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/net.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/af_unix.h>

#define MAX_PKT  256
#define __PATH_LEN_U64__ 
#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

struct uds_data_t {
    u32 len;
    u32 dst_pid;
    u32 src_pid;
    u32 uid;
    u32 gid;
    u8  pth[UNIX_PATH_MAX];
    u8  pkt[MAX_PKT];
};

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(unix_data, struct uds_data_t, 1);

BPF_PERF_OUTPUT(unix_msg_events);

int trace_unix_stream_read_actor(struct pt_regs *ctx)
{
    u8* sock_path;
    u32 zero = 0;
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct unix_address *addr;
    u8 path[UNIX_PATH_MAX] = {0};

    FILTER_PID

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb->sk->sk_family != AF_UNIX)
        return 0;

    struct uds_data_t *data = unix_data.lookup(&zero);
    if (!data)
        return 0;

    struct unix_sock *usk = unix_sk(skb->sk);
    if (!usk)
        return 0;

    addr = usk->addr;
    if (addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        bpf_probe_read(&path, UNIX_PATH_MAX, sock_path);
    }

    struct unix_sock *pusk = unix_sk(usk->peer);
    if (!pusk)
        return 0;

    addr = pusk->addr;
    if (addr->len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        bpf_probe_read(&path, UNIX_PATH_MAX, sock_path);
    }

    data->dst_pid = (u32)skb->sk->sk_peer_pid->numbers[0].nr;
    data->src_pid = (u32)usk->peer->sk_peer_pid->numbers[0].nr;
    data->uid = (u32)skb->sk->sk_peer_cred->uid.val;
    data->gid = (u32)skb->sk->sk_peer_cred->gid.val;
    bpf_probe_read(&data->pth, UNIX_PATH_MAX, sock_path);

    u32 data_len = skb->len;
    if(data_len > MAX_PKT)
        return 0;
    data->len = data_len;

    void *iodata = (void *)skb->data;

    bpf_probe_read(data->pkt, data_len, iodata);

    unix_msg_events.perf_submit(ctx, data, sizeof(struct uds_data_t));

    return 0;
}
"""

    if len(pids) >= 1:
        first_if = '&&'.join([f"pid!={pid}" for pid in pids])
        bpf_text = bpf_text.replace('FILTER_PID', f'if ({first_if}) return 0;')
    else:
        bpf_text = bpf_text.replace('FILTER_PID', '')
    if debug:
        print(bpf_text)
    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="unix_stream_read_actor", fn_name="trace_unix_stream_read_actor")
    # read events
    b["unix_msg_events"].open_perf_buffer(print_pkg)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            b.detach_kprobe(event="unix_stream_read_actor")
            print("stop due to Ctrl-C")
            return


if __name__ == "__main__":
    # hook_uds_msg([239123, 239384], debug=True)
    hook_uds_msg([], debug=True)
