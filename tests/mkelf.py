#!/usr/bin/env python3
"""Emit a tiny hand-assembled ELF64 x86_64 executable (sections + symtab) to test the ELF loader."""
import struct, sys

BASE = 0x400000
TEXT_OFF = 0x1000
TEXT_VA = BASE + TEXT_OFF
RO_OFF = 0x2000
RO_VA = BASE + RO_OFF

msg = b"hello from elf\x00"
msg2 = b"second string here\x00"

# layout of .text: _start, func_a, func_b
start_va = TEXT_VA
a_va = TEXT_VA + 0x20
b_va = TEXT_VA + 0x50

def rel32(src_end, dst): return struct.pack("<i", dst - src_end)

# func_b: push rbp; mov rbp,rsp; mov eax,1; cmp edi,2; jl +2; mov eax,2; pop rbp; ret
func_b = bytes([0x55, 0x48, 0x89, 0xe5, 0xb8, 1, 0, 0, 0, 0x83, 0xff, 0x02, 0x7c, 0x05, 0xb8, 2, 0, 0, 0, 0x5d, 0xc3])
# func_a: push rbp; mov rbp,rsp; lea rdi,[rip+msg]; call func_b; lea rsi,[rip+msg2]; xor eax,eax; pop rbp; ret
a = bytearray([0x55, 0x48, 0x89, 0xe5])
a += bytes([0x48, 0x8d, 0x3d]); a += rel32(a_va + len(a) + 4, RO_VA)
a += bytes([0xe8]); a += rel32(a_va + len(a) + 4, b_va)
a += bytes([0x48, 0x8d, 0x35]); a += rel32(a_va + len(a) + 4, RO_VA + len(msg))
a += bytes([0x31, 0xc0, 0x5d, 0xc3])
func_a = bytes(a)
# _start: call func_a; mov eax,60; xor edi,edi; syscall
s = bytearray([0xe8]); s += rel32(start_va + 5, a_va)
s += bytes([0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05])
start = bytes(s)

text = bytearray(0x80)
text[0:len(start)] = start
text[0x20:0x20 + len(func_a)] = func_a
text[0x50:0x50 + len(func_b)] = func_b
for i in range(len(text)):
    pass
rodata = msg + msg2

shstr = b"\x00.text\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00"
def off(n): return shstr.index(n.encode() + b"\x00")

strtab = b"\x00_start\x00func_a\x00func_b\x00"
def soff(n): return strtab.index(b"\x00" + n.encode() + b"\x00") + 1
def sym(name, val, size, info, shndx): return struct.pack("<IBBHQQ", soff(name) if name else 0, info, 0, shndx, val, size)
symtab = sym("", 0, 0, 0, 0) + sym("_start", start_va, len(start), 0x12, 1) + sym("func_a", a_va, len(func_a), 0x12, 1) \
       + sym("func_b", b_va, len(func_b), 0x12, 1)

SYM_OFF = 0x2100
STR_OFF = SYM_OFF + len(symtab)
SHSTR_OFF = STR_OFF + len(strtab)
SH_OFF = (SHSTR_OFF + len(shstr) + 7) & ~7

def shdr(name, typ, flags, addr, off_, size, link=0, info=0, align=1, entsize=0):
    return struct.pack("<IIQQQQIIQQ", off(name) if name else 0, typ, flags, addr, off_, size, link, info, align, entsize)

shdrs = shdr(None, 0, 0, 0, 0, 0)
shdrs += shdr(".text", 1, 6, TEXT_VA, TEXT_OFF, len(text), align=16)
shdrs += shdr(".rodata", 1, 2, RO_VA, RO_OFF, len(rodata), align=1)
shdrs += shdr(".symtab", 2, 0, 0, SYM_OFF, len(symtab), link=4, info=1, align=8, entsize=24)
shdrs += shdr(".strtab", 3, 0, 0, STR_OFF, len(strtab))
shdrs += shdr(".shstrtab", 3, 0, 0, SHSTR_OFF, len(shstr))

ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, start_va, 64, SH_OFF, 0, 64, 56, 2, 64, 6, 5)
phdrs = struct.pack("<IIQQQQQQ", 1, 5, TEXT_OFF, TEXT_VA, TEXT_VA, len(text), len(text), 0x1000)      # R+X
phdrs += struct.pack("<IIQQQQQQ", 1, 4, RO_OFF, RO_VA, RO_VA, len(rodata), len(rodata), 0x1000)      # R

img = bytearray(SH_OFF + len(shdrs))
img[0:len(ehdr)] = ehdr
img[64:64 + len(phdrs)] = phdrs
img[TEXT_OFF:TEXT_OFF + len(text)] = text
img[RO_OFF:RO_OFF + len(rodata)] = rodata
img[SYM_OFF:SYM_OFF + len(symtab)] = symtab
img[STR_OFF:STR_OFF + len(strtab)] = strtab
img[SHSTR_OFF:SHSTR_OFF + len(shstr)] = shstr
img[SH_OFF:] = shdrs
open(sys.argv[1], "wb").write(img)
