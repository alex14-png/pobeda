#!/usr/bin/env python3
# interpreter.py
# CLI interpreter for Variant #9
# Usage:
#  python interpreter.py program.bin memory_dump.csv 100-220
# memory is word-addressable (32-bit words). cmd and data memories are separate.

import argparse
import csv
import math
from src.utils import mask
from pathlib import Path

def get_instr_size(cmd_int):
    """Определяет размер инструкции по целому числу команды"""
    # Извлекаем только первые 3 бита (поле A)
    A = cmd_int & 0b111
    
    if A == 3:  # LOAD_CONST
        return 5
    elif A == 7:  # READ_MEM
        return 2
    elif A == 2:  # WRITE_MEM
        return 2
    elif A == 4:  # SQRT
        return 2
    else:
        raise ValueError(f"Unknown opcode A={A} (full byte: {cmd_int})")

#INSTR_SIZE = 4  # bytes per instruction

def run_binary_bytes(code_bytes, data_mem_size=1<<16, regs_count=32):
    """Альтернативная функция для запуска из байтов (без файла)"""
    # Инициализация состояния
    state = {
        "regs": [0]*regs_count,
        "data_mem": [0]*data_mem_size
    }

    # Выполнение инструкций последовательно
    pc = 0
    code_len = len(code_bytes)
    while pc < code_len:
        if pc >= code_len:
            break
        opcode = code_bytes[pc]  # First byte is opcode
        instr_size = get_instr_size(opcode)
        if pc + instr_size > code_len:
            break
        instr_bytes = code_bytes[pc:pc+instr_size]
        decode_and_execute_one(instr_bytes, state)
        pc += instr_size

    return state


def decode_and_execute_one(cmd_int, state):
    """
    cmd_int: 32-bit integer instruction
    state: dict with keys:
       regs: list of int (registers)
       data_mem: list of ints (word-addressable)
    Returns None.
    """
    cmd_int = int.from_bytes(cmd_int, "little")
    A = cmd_int & mask(3)
    if A == 3:  # LOAD_CONST
        B = (cmd_int >> 3) & mask(3)   # constant
        C = (cmd_int >> 6) & mask(28)   # dest reg
        state["regs"][B] = C
    elif A == 7:  # READ_MEM
        B = (cmd_int >> 3) & mask(3)    # dest reg
        C = (cmd_int >> 6) & mask(3)  # mem addr
        state["regs"][C] = state["data_mem"][B]
    elif A == 2:  # WRITE_MEM
        B = (cmd_int >> 3) & mask(3)   # mem addr
        C = (cmd_int >> 6) & mask(3)   # source reg
        state["data_mem"][C] = state["regs"][B]
    elif A == 4:  # SQRT
        B = (cmd_int >> 3) & mask(3)    # dest reg
        C = (cmd_int >> 6) & mask(3)  # mem addr
        val = state["data_mem"][B]
        if val < 0:
            raise ValueError("SQRT on negative value")
        # integer sqrt (floor)
        state["regs"][C] = math.isqrt(int(val))
    else:
        #pass
        raise ValueError(f"Unknown opcode A={A}")

def run_program(bin_path, data_mem_size=1<<16, regs_count=32, dump_csv=None, dump_range=None):
    # read binary
    p = Path(bin_path)
    if not p.exists():
        raise FileNotFoundError(bin_path)
    with open(p, "rb") as f:
        code = f.read()

    # initialize state
    state = {
        "regs": [0]*regs_count,
        "data_mem": [0]*data_mem_size
    }

    # execute instructions sequentially
    pc = 0
    code_len = len(code)
    while pc < code_len:
        if pc >= code_len:
            break
        opcode = code[pc]  # First byte is opcode
        instr_size = get_instr_size(opcode)
        if pc + instr_size > code_len:
            break
        instr_bytes = code[pc:pc+instr_size]
        decode_and_execute_one(instr_bytes, state)
        pc += instr_size

    # dump CSV if requested
    if dump_csv is not None and dump_range is not None:
        start, end = dump_range
        with open(dump_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["address", "value"])
            if start < 0 or end >= data_mem_size:
                raise IndexError("Dump range out of bounds")
            for addr in range(start, end+1):
                writer.writerow([addr, state["data_mem"][addr]])
    return state

def parse_range(s):
    # format "start-end"
    if "-" not in s:
        raise argparse.ArgumentTypeError("Range must be start-end")
    a,b = s.split("-",1)
    return (int(a), int(b))

def main():
    parser = argparse.ArgumentParser(description="Interpreter for UVM Variant #9")
    parser.add_argument("binary", help="Path to binary program")
    parser.add_argument("dump_csv", help="Path to CSV dump file (address,value)")
    parser.add_argument("range", help="Memory dump range start-end (e.g. 100-220)")
    parser.add_argument("--mem-size", type=int, default=1<<16, help="Data memory size (words)")
    parser.add_argument("--regs", type=int, default=32, help="Number of registers")
    args = parser.parse_args()

    dump_range = parse_range(args.range)
    state = run_program(args.binary, data_mem_size=args.mem_size, regs_count=args.regs,
                        dump_csv=args.dump_csv, dump_range=dump_range)
    print("Program executed. Dump written to", args.dump_csv)

if __name__ == "__main__":
    main()
