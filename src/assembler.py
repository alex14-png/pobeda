import argparse
import yaml
from src.utils import pack_fields, mask
from pathlib import Path


def encode_instr(ir):
    cmd_name = ir["cmd"]
    if cmd_name == "LOAD_CONST":
        A = 3
        B = int(ir["value"])
        C = int(ir["reg"])
        val = pack_fields([(A,0,3), (B,3,3), (C,6,28)])
        return val.to_bytes(5, "little")
    elif cmd_name == "READ_MEM":
        A = 7
        B = int(ir["reg"])
        C = int(ir["addr"])
        val = pack_fields([(A,0,3), (B,3,3), (C,6,3)])
        return val.to_bytes(2, "little")
    elif cmd_name == "WRITE_MEM":
        A = 2
        B = int(ir["addr"])
        C = int(ir["src_reg"])
        val = pack_fields([(A,0,3), (B,3,3), (C,6,3)])
        return val.to_bytes(2, "little")
    elif cmd_name == "SQRT":
        A = 4
        B = int(ir["reg"])
        C = int(ir["addr"])
        val = pack_fields([(A,0,3), (B,3,3), (C,6,3)])
        return val.to_bytes(2, "little")
    else:
        raise ValueError(f"Unknown IR command: {cmd_name}")

def parse_yaml(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "program" not in data:
        raise ValueError("YAML must contain top-level 'program' list")
    return data["program"]

def to_ir(yaml_program):
    ir = []
    for idx, instr in enumerate(yaml_program):
        cmd = instr.get("cmd")
        if cmd == "LOAD_CONST":
            if "reg" not in instr or "value" not in instr:
                raise ValueError(f"LOAD_CONST missing fields at instr {idx}")
            ir.append({"cmd":"LOAD_CONST", "reg":int(instr["reg"]), "value":int(instr["value"])})
        elif cmd == "READ_MEM":
            if "reg" not in instr or "addr" not in instr:
                raise ValueError(f"READ_MEM missing fields at instr {idx}")
            ir.append({"cmd":"READ_MEM", "reg":int(instr["reg"]), "addr":int(instr["addr"])})
        elif cmd == "WRITE_MEM":
            if ("src_reg" not in instr) or (("offset" not in instr) and ("addr" not in instr)):
                raise ValueError(f"WRITE_MEM missing fields at instr {idx}")
            addr = instr.get("offset", instr.get("addr"))
            ir.append({"cmd":"WRITE_MEM", "addr":int(addr), "src_reg":int(instr["src_reg"])})
        elif cmd == "SQRT":
            if "reg" not in instr or "addr" not in instr:
                raise ValueError(f"SQRT missing fields at instr {idx}")
            ir.append({"cmd":"SQRT", "reg":int(instr["reg"]), "addr":int(instr["addr"])})
        else:
            raise ValueError(f"Unknown command '{cmd}' at index {idx}")
    return ir

def assemble(ir_list):
    binary = bytearray()
    for instr in ir_list:
        binary.extend(encode_instr(instr))
    return binary

def fmt_bytes_hex(b: bytes):
    return ", ".join(f"0x{x:02X}" for x in b)

def main():
    parser = argparse.ArgumentParser(description="Assembler for UVM Variant #9 (YAML -> BIN)")
    parser.add_argument("input", help="Path to YAML input (program)")
    parser.add_argument("output", help="Path to binary output")
    parser.add_argument("--test", action="store_true", help="Test mode: print IR and bytes")
    args = parser.parse_args()

    prog = parse_yaml(args.input)
    ir = to_ir(prog)

    if args.test:
        print("=== IR ===")
        for i, instr in enumerate(ir):
            print(f"{i:03}: {instr}")
    binary = assemble(ir)
    with open(args.output, "wb") as f:
        f.write(binary)

    print(f"Wrote binary '{args.output}' ({len(binary)} bytes).")

    if args.test:
        print("Bytes (hex):")
        print(fmt_bytes_hex(binary))

if __name__ == "__main__":
    main()
