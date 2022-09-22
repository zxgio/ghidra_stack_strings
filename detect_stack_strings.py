# Detect stack-strings written by the selected instructions, emulated using Unicorn.
# The script is written in Python 3, so it needs Ghidrathon.
# @author zxgio
# @category Emulation
# @keybinding
# @menupath
# @toolbar

import re
from collections import namedtuple
from itertools import chain
from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_MODE_64,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_MEM_WRITE,
    UC_HOOK_MEM_WRITE,
)
from unicorn.x86_const import (
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
    UC_X86_REG_EBP,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_RBP,
)

# functions ascii_strings and unicode_strings are taken from:
# https://gist.github.com/jedimasterbot/39ef35bc4324e4b4338a210298526cd0

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
String = namedtuple("String", ["s", "offset"])


def ascii_strings(buf, n=4):
    reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())


def unicode_strings(buf, n=4):
    reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def all_strings(buf, n=4):
    return list(chain(ascii_strings(buf, n), unicode_strings(buf, n)))


def emulate():
    proc = currentProgram.getLanguage().getProcessor().toString()
    if proc != "x86":
        print("Sorry, unsupported architecture.")
        return
    bits = currentProgram.getLanguage().getLanguageDescription().getSize()
    if bits == 32:
        emu = Uc(UC_ARCH_X86, UC_MODE_32)
    else:
        emu = Uc(UC_ARCH_X86, UC_MODE_64)
    min_addr = currentSelection.getMinAddress().getOffset()
    max_addr = currentSelection.getMaxAddress()
    # print(f'Selection from 0x{min_addr:x} to 0x{max_addr.getOffset():x}')
    last_instruction = getInstructionContaining(max_addr)
    max_addr = last_instruction.getMaxAddress().getOffset()
    last_instruction_addr = last_instruction.getMinAddress().getOffset()
    print(
        f"Emulating from 0x{min_addr:x} to 0x{last_instruction_addr:x} (code range 0x{min_addr:x}-0x{max_addr:x})"
    )
    code = bytes(b & 0xFF for b in getBytes(toAddr(min_addr), max_addr - min_addr + 1))
    CODE_ADDR = min_addr & ~4095
    CODE_SIZE = (max_addr - CODE_ADDR + 4096) & ~4095
    STACK_ADDR = 1024 * 1024
    STACK_SIZE = 1024 * 1024
    emu.mem_map(CODE_ADDR, CODE_SIZE, UC_PROT_EXEC)
    emu.mem_write(min_addr, code)
    emu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    if bits == 32:
        emu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE)
        emu.reg_write(UC_X86_REG_EBP, STACK_ADDR + STACK_SIZE // 2)
    else:
        emu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE)
        emu.reg_write(UC_X86_REG_RBP, STACK_ADDR + STACK_SIZE // 2)
    all_writes = {}

    def hook_mem_write(emu, access, address, size, value, user_data):
        assert access == UC_MEM_WRITE
        # print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        all_writes[address] = emu.reg_read(
            UC_X86_REG_EIP if bits == 32 else UC_X86_REG_RIP
        )

    emu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    emu.emu_start(min_addr, last_instruction_addr)
    found = False
    for s, offset in all_strings(emu.mem_read(STACK_ADDR, STACK_SIZE), 3):
        found = True
        inst_addr = all_writes[offset + STACK_ADDR]
        print(f"'{s}' written by instruction at 0x{inst_addr:x}")
        setPreComment(toAddr(inst_addr), s)
    if not found:
        print('No strings found.')


if currentSelection is not None:
    emulate()
else:
    print("Please select the instructions to emulate, before running this script.")
