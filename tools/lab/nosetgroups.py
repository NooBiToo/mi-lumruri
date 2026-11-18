"""Лабораторная обёртка: запускает программу с seccomp-фильтром, при котором setgroups() возвращает 0 без действия.
Нужна только в одноразовом user namespace лаборатории: там setgroups запрещён ядром (/proc/self/setgroups = deny),
а nfqws2 при сбросе привилегий завершается на нём. На роутере не используется.
  nosetgroups.py <программа> [аргументы...]"""
import ctypes
import os
import struct
import sys

AUDIT_ARCH_X86_64 = 0xC000003E
NR_SETGROUPS = 116  # x86_64
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
BPF_LD_W_ABS, BPF_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06


def ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


prog = b"".join([
    ins(BPF_LD_W_ABS, 0, 0, 4),                     # arch
    ins(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
    ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ins(BPF_LD_W_ABS, 0, 0, 0),                     # номер системного вызова
    ins(BPF_JEQ_K, 0, 1, NR_SETGROUPS),
    ins(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 0),    # setgroups → 0
    ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
])
buf = ctypes.create_string_buffer(prog)
fprog = struct.pack("HxxxxxxQ", len(prog) // 8, ctypes.addressof(buf))
fbuf = ctypes.create_string_buffer(fprog)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
    sys.exit(f"PR_SET_NO_NEW_PRIVS: {os.strerror(ctypes.get_errno())}")
if libc.prctl(22, 2, ctypes.addressof(fbuf), 0, 0) != 0:  # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
    sys.exit(f"PR_SET_SECCOMP: {os.strerror(ctypes.get_errno())}")
os.execv(sys.argv[1], sys.argv[1:])
