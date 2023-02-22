import os
import signal
import concurrent.futures.process

from bcc import BPF
from hashlib import md5
from concurrent.futures import ProcessPoolExecutor, as_completed

local_prog = '''
static u16 local_strlen(u8 * data){
    u16 i = 0;
    for (; i < 0x80; i++){
        if (data[i] == '\\0') {break;}
    }
    return i - 1;
}
static u16 local_strcpy(u8 * dst, u8 * src, u16 len){
    u16 i = 0;
    u16 dst_len = local_strlen(dst);
    u16 src_len = local_strlen(src);
    for(; i < 0x80; i++){
        if (i >= len || i >= dst_len || i >= src_len || dst[i] == '\\0' || src[i] == '\\0') {break;}
        dst[i] = src[i];
    }
    return i - 1;
}
'''
executor = None


def get_variable_by_type(arg_idx: int, arg_type: str, func: str):
    bpf_prog = "\n{\n"

    if arg_type == "char*":
        bpf_prog += f'''\tchar str[0x80];\n\tbpf_probe_read_user(&str, 0x80, (void *)PT_REGS_PARM{arg_idx}(ctx));\n\tbpf_trace_printk("[{func}-{arg_idx - 1}] %s\\n", &str);'''
    elif arg_type == "char**":
        bpf_prog += f'''\tsize_t ptr;\n\tchar str[0x90]\n\t;char whole[0x110];\n\tu8 off = 0;\n\twhile(off <= 8)\n\t'''
        bpf_prog += '''{'''
        bpf_prog += f'''
\t\tbpf_probe_read_user(&ptr, sizeof(size_t), (void *)PT_REGS_PARM{arg_idx}(ctx)+sizeof(size_t) * off);
\t\tif (!ptr) break;
\t\t__builtin_memset(str, 0, 0x80);
\t\tbpf_probe_read_user(&str, 0x80, (void *)ptr);
\t\tbpf_trace_printk("[{func}-{arg_idx - 1}][%d] %s\\n", off, &str);
\t\toff++;\n\t'''
        bpf_prog += '''};\n\t'''
    elif arg_type == "u8":
        bpf_prog += f'''\tu8 val = 0;\n\tbpf_probe_read_user(&val, 0x1, (void *)PT_REGS_PARM{arg_idx}(ctx));\n\tbpf_trace_printk("[{func}] %x\\n", val);'''
    elif arg_type == "u16":
        bpf_prog += f'''\tu16 val = 0;\n\tbpf_probe_read_user(&val, 0x2, (void *)PT_REGS_PARM{arg_idx}(ctx));\n\tbpf_trace_printk("[{func}] %x\\n", val);'''
    elif arg_type == "u32":
        bpf_prog += f'''\tu32 val = 0;\n\tbpf_probe_read_user(&val, 0x4, (void *)PT_REGS_PARM{arg_idx}(ctx));\n\tbpf_trace_printk("[{func}] %lx\\n", val);'''
    elif arg_type == "u64":
        bpf_prog += f'''\tu64 val = 0;\n\tbpf_probe_read_user(&val, 0x8, (void *)PT_REGS_PARM{arg_idx}(ctx));\n\tbpf_trace_printk("[{func}] %llx\\n", val);'''
    bpf_prog += "\n}"
    return bpf_prog


def hash_func(func_name: str):
    return md5(func_name.encode('latin-1')).hexdigest()[:8]


def generate_hooks(hooks: list, pids: list, debug=False):
    bpf_progs = {}

    assert len(pids) >= 1
    for pid in pids:
        assert isinstance(pid, int), "malformed pid"

    for hook in hooks:
        assert isinstance(hook, dict) and "func" in hook.keys() and "args" in hook.keys(), "malformed hook"
        assert isinstance(hook["func"], str), "malformed hook.func"
        assert isinstance(hook["args"], list) and len(hook["args"]) >= 1, "malformed hook.args"
        hashed_func = hash_func(hook["func"])
        bpf_prog = f'''#include <uapi/linux/ptrace.h>\n{local_prog}\nint watch_{hashed_func}(struct pt_regs *ctx)\n'''
        bpf_prog += '''{\n\t'''
        for arg in hook["args"]:
            assert isinstance(arg, tuple) and isinstance(arg[0], int) and isinstance(arg[1], str) and 1 <= arg[
                0] <= 5, "malformed hook.args.arg"

        first_if = "||".join([f"!PT_REGS_PARM{arg[0]}(ctx)" for arg in hook["args"] if "*" in arg[1]])
        bpf_prog += f"if ({first_if}) return 0;\n\t"

        bpf_prog += "u64 pid_tgid = bpf_get_current_pid_tgid();\n\t"
        bpf_prog += "u32 pid = pid_tgid >> 32;\n\t"

        second_if = "&&".join([f"pid!={pid}" for pid in pids])
        bpf_prog += f"if ({second_if}) return 0;\n\t"

        for arg in hook["args"]:
            bpf_prog += get_variable_by_type(arg[0], arg[1], hook["func"])

        bpf_prog += '''\n\treturn 0;\n};'''

        if debug:
            print(bpf_prog)

        bpf_progs[hook["func"]] = bpf_prog

    return bpf_progs


def execute_one_hook(bpf_progs, func):
    global executor
    try:
        b = BPF(text=bpf_progs[func])
        hashed_func = hash_func(func)
        b.attach_uprobe(name="c", sym=func, fn_name=f"watch_{hashed_func}")
        while True:
            try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                if msg == "":
                    continue
                print("%-18.9f %-16s %-6d %s" % (ts, task.decode("latin-1"), pid, msg.decode("latin-1")))
            except ValueError as e:
                print(e)
                continue
    except KeyboardInterrupt:
        return


def attach_hooks(executor, bpf_progs: dict):
    print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "DATA"))
    procs = []
    for _func in bpf_progs.keys():
        procs.append(executor.submit(execute_one_hook, bpf_progs, _func))
    try:
        for future in as_completed(procs):
            return
    except KeyboardInterrupt:
        print("stop due to Ctrl-C")


def hook(hooks: list, pids: list, debug=False):
    global executor
    _bpf_progs = generate_hooks(hooks=_hooks, pids=pids, debug=debug)
    executor = ProcessPoolExecutor(max_workers=len(_hooks))
    attach_hooks(executor, _bpf_progs)


if __name__ == "__main__":
    DEBUG = True
    BPFs = []
    _hooks = [
        {
            "func": "system",
            "args": [
                (1, "char*")
            ]
        }, {
            "func": "execve",
            "args": [
                # (1, "char*"),
                (2, "char**")
            ]
        }
    ]
    hook(hooks=_hooks, pids=[251662, 2007612, 2129010, 2129011, 3454680], debug=DEBUG)
