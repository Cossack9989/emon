import os

from bcc import BPF
from hexdump import hexdump

from logger import logger


def hook_pipe_msg(pids: list, debug=False):

    def print_pkg(cpu, data, size):
        event = b["pipe_msg_events"].event(data)
        typ = ''
        if chr(event.typ) == 'I':
            typ = 'IOVEC'
        elif chr(event.typ) == 'K':
            typ = 'KVEC'
        else:
            typ = 'UNK'
        logger.info(f"pipe_write in {typ} by {event.pid} to inode:{event.ino}(uid={event.creator})")
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
#include <uapi/linux/uio.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/minmax.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/sch_generic.h>

#define MAX_PKT  256

struct pipe_data_t {
    u32 len;
    u32 pid;
    u32 creator;
    u32 ino;
    u8 typ;
    u8 pkt[MAX_PKT];
};

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(pipe_data, struct pipe_data_t, 1);

BPF_PERF_OUTPUT(pipe_msg_events);

int trace_pipe_write(struct pt_regs *ctx){
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    FILTER_PID

    struct pipe_data_t *data = pipe_data.lookup(&zero);
    if (!data)
        return 0;

    struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
    if (!iocb)
        return 0;
    
    struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2(ctx);
    if (!from)
        return 0;

    struct file *curr_filp = iocb->ki_filp;
    struct pipe_inode_info *curr_pipe = iocb->ki_filp->private_data;

    if ((curr_filp->f_path.dentry->d_inode->i_mode & S_IFMT) != S_IFIFO)
        return 0;

    data->pid = pid;
    data->creator = curr_pipe->user->uid.val;
    data->ino = curr_filp->f_path.dentry->d_inode->i_ino;
    // bpf_probe_read_kernel(data->pth, DNAME_INLINE_LEN, curr_filp->f_path.dentry->d_iname);

    u32 len = from->count;
    u32 off = from->iov_offset;
    if (from->iter_type == ITER_IOVEC){
        u32 cap = from->iov->iov_len;
        u8 * src = (u8*)(from->iov->iov_base + off);
        if (off + len > cap || len > MAX_PKT)
            return 0;
        bpf_probe_read(data->pkt, len, src);
        data->len = len;
        data->typ = 'I';
        pipe_msg_events.perf_submit(ctx, data, sizeof(struct pipe_data_t));
    }
    else if (from->iter_type == ITER_KVEC){
        u32 cap = from->kvec->iov_len;
        u8 * src = (u8*)(from->kvec->iov_base + off);
        if (off + len > cap || len > MAX_PKT)
            return 0;
        bpf_probe_read(data->pkt, len, src);
        data->len = len;
        data->typ = 'K';
        pipe_msg_events.perf_submit(ctx, data, sizeof(struct pipe_data_t));
    }

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
    b.attach_kprobe(event="pipe_write", fn_name="trace_pipe_write")
    # read events
    b["pipe_msg_events"].open_perf_buffer(print_pkg)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            b.detach_kprobe(event="pipe_write")
            print("stop due to Ctrl-C")
            return
    return


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
        if os.path.exists(pth):
            pth += f" ({oct(os.stat(pth).st_mode)})"
        logger.info(f"LEN: {event.len}\tPATH: {pth}")
        logger.info(f"PID: {event.src_pid}(uid={event.src_uid};gid={event.src_gid})->{event.dst_pid}(uid={event.dst_uid};gid={event.dst_gid})")
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
    u32 dst_uid;
    u32 dst_gid;
    u32 src_pid;
    u32 src_uid;
    u32 src_gid;
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

    data->src_pid = (u32)usk->peer->sk_peer_pid->numbers[0].nr;
    data->src_uid = (u32)usk->peer->sk_peer_cred->uid.val;
    data->src_gid = (u32)usk->peer->sk_peer_cred->gid.val;
    data->dst_pid = (u32)skb->sk->sk_peer_pid->numbers[0].nr;
    data->dst_uid = (u32)skb->sk->sk_peer_cred->uid.val;
    data->dst_gid = (u32)skb->sk->sk_peer_cred->gid.val;

    if (data->src_pid == data->dst_pid)
        return 0;

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
    hook_pipe_msg([], debug=True)
