#!/usr/bin/env python3
import sys
from collections import defaultdict

MASK32 = 0xFFFFFFFF

#--------------------------------- FUNCTIONS -----------------------------------
def get_bits(x, hi, lo):
    """Extract bits [hi:lo] inclusive from x."""
    width = hi - lo + 1
    return (x >> lo) & ((1 << width) - 1)

def decode_instruction(instr):
    """
    Decode a 32-bit RISC-V instruction.
    Returns dict with opcode, funct3, funct7, and instruction type.
    """
    d = {}
    d["instr"] = instr & MASK32
    d["opcode"] = get_bits(instr, 6, 0)
    d["rd"] = get_bits(instr, 11, 7)
    d["funct3"] = get_bits(instr, 14, 12)
    d["rs1"] = get_bits(instr, 19, 15)
    d["rs2"] = get_bits(instr, 24, 20)
    d["funct7"] = get_bits(instr, 31, 25)
    return d

def get_mnemonic(d):
    """Get instruction mnemonic from decoded instruction."""
    op = d["opcode"]
    f3 = d["funct3"]
    f7 = d["funct7"]
    
    if d["instr"] == 0:
        return "nop"
    
    # R-type (0x33)
    if op == 0x33:
        if f3 == 0b000:
            return "sub" if f7 == 0b0100000 else "add"
        elif f3 == 0b001:
            return "sll"
        elif f3 == 0b010:
            return "slt"
        elif f3 == 0b011:
            return "sltu"
        elif f3 == 0b100:
            return "xor"
        elif f3 == 0b101:
            return "sra" if f7 == 0b0100000 else "srl"
        elif f3 == 0b110:
            return "or"
        elif f3 == 0b111:
            return "and"
    
    # I-type ALU (0x13)
    elif op == 0x13:
        if f3 == 0b000:
            return "addi"
        elif f3 == 0b001:
            return "slli"
        elif f3 == 0b010:
            return "slti"
        elif f3 == 0b011:
            return "sltiu"
        elif f3 == 0b100:
            return "xori"
        elif f3 == 0b101:
            return "srai" if f7 == 0b0100000 else "srli"
        elif f3 == 0b110:
            return "ori"
        elif f3 == 0b111:
            return "andi"
    
    # Load (0x03)
    elif op == 0x03:
        if f3 == 0b000:
            return "lb"
        elif f3 == 0b001:
            return "lh"
        elif f3 == 0b010:
            return "lw"
        elif f3 == 0b100:
            return "lbu"
        elif f3 == 0b101:
            return "lhu"
    
    # Store (0x23)
    elif op == 0x23:
        if f3 == 0b000:
            return "sb"
        elif f3 == 0b001:
            return "sh"
        elif f3 == 0b010:
            return "sw"
    
    # Branch (0x63)
    elif op == 0x63:
        if f3 == 0b000:
            return "beq"
        elif f3 == 0b001:
            return "bne"
        elif f3 == 0b100:
            return "blt"
        elif f3 == 0b101:
            return "bge"
        elif f3 == 0b110:
            return "bltu"
        elif f3 == 0b111:
            return "bgeu"
    
    # JAL (0x6F)
    elif op == 0x6F:
        return "jal"
    
    # JALR (0x67)
    elif op == 0x67:
        return "jalr"
    
    # LUI (0x37)
    elif op == 0x37:
        return "lui"
    
    # AUIPC (0x17)
    elif op == 0x17:
        return "auipc"
    
    # ECALL/EBREAK (0x73)
    elif op == 0x73:
        if d["instr"] == 0x00000073:
            return "ecall"
        elif d["instr"] == 0x00100073:
            return "ebreak"
    
    return "unknown"

def categorize_instruction(mnemonic):
    """
    Categorize instruction into one of:
    - ALU: Arithmetic/Logic operations
    - Memory: Loads and stores
    - Branch: Conditional branches
    - Control: Unconditional jumps and system calls
    - Other: Unknown or special instructions
    """
    alu_instructions = {
        'add', 'sub', 'addi', 'and', 'or', 'xor', 'andi', 'ori', 'xori',
        'sll', 'srl', 'sra', 'slli', 'srli', 'srai',
        'slt', 'sltu', 'slti', 'sltiu',
        'lui', 'auipc'
    }
    
    memory_instructions = {
        'lw', 'lh', 'lb', 'lhu', 'lbu',
        'sw', 'sh', 'sb'
    }
    
    branch_instructions = {
        'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu'
    }
    
    control_instructions = {
        'jal', 'jalr', 'ecall', 'ebreak'
    }
    
    if mnemonic in alu_instructions:
        return "ALU"
    elif mnemonic in memory_instructions:
        return "Memory"
    elif mnemonic in branch_instructions:
        return "Branch"
    elif mnemonic in control_instructions:
        return "Control"
    elif mnemonic == "nop":
        return "Other"
    else:
        return "Other"
    
def analyze_instruction_mix(instructions):
    """
    Analyze instruction mix and return statistics.
    
    Returns:
        dict with category counts and percentages
    """
    stats = {
        "ALU": 0,
        "Memory": 0,
        "Branch": 0,
        "Control": 0,
        "Other": 0
    }
    
    mnemonic_counts = defaultdict(int)
    category_details = defaultdict(list)
    
    total = len(instructions)
    
    for instr in instructions:
        d = decode_instruction(instr)
        mnem = get_mnemonic(d)
        category = categorize_instruction(mnem)
        
        stats[category] += 1
        mnemonic_counts[mnem] += 1
        category_details[category].append(mnem)
    
    # Calculate percentages
    percentages = {}
    for cat in stats:
        if total > 0:
            percentages[cat] = (stats[cat] / total) * 100
        else:
            percentages[cat] = 0.0
    
    return {
        "counts": stats,
        "percentages": percentages,
        "mnemonic_counts": dict(mnemonic_counts),
        "total": total
    }

#----------------------------- TEST THE FUNCTIONS----------------------------------------------

def test_get_bits():
    # Test extracting lower 8 bits
    assert get_bits(0xABCD, 7, 0) == 0xCD
    # Test extracting bits 15-8
    assert get_bits(0xABCD, 15, 8) == 0xAB
    # Test with RISC-V instruction (addi x1, x2, 10)
    instr = 0x00A10093  # addi x1, x2, 10
    opcode = get_bits(instr, 6, 0)
    assert opcode == 0x13  # I-type opcode
    print("get_bits tests passed!")

def test_decode_instruction():
    # Test with R-type: add x1, x2, x3
    # NOTE: your original encoding was wrong
    add_instr = 0x003100B3  # correct encoding for add x1, x2, x3
    decoded = decode_instruction(add_instr)
    assert decoded["opcode"] == 0x33
    assert decoded["rd"] == 1
    assert decoded["rs1"] == 2
    assert decoded["rs2"] == 3
    assert decoded["funct3"] == 0
    assert decoded["funct7"] == 0
    
    # Test with I-type: addi x1, x2, 10
    addi_instr = 0x00A10093
    decoded = decode_instruction(addi_instr)
    assert decoded["opcode"] == 0x13
    assert decoded["rd"] == 1
    assert decoded["rs1"] == 2
    
    print("decode_instruction tests passed!")

def test_get_mnemonic():
    # Test R-type: add x1, x2, x3
    add_instr = 0x003100B3  # correct encoding for add x1, x2, x3
    decoded = decode_instruction(add_instr)
    mnemonic = get_mnemonic(decoded)
    assert mnemonic == "add"
    
    # Test I-type: addi x1, x2, 10
    addi_instr = 0x00A10093
    decoded = decode_instruction(addi_instr)
    mnemonic = get_mnemonic(decoded)
    assert mnemonic == "addi"
    
    print("get_mnemonic tests passed!")

def test_categorize_instruction():
    assert categorize_instruction("add") == "ALU"
    assert categorize_instruction("lw") == "Memory"
    assert categorize_instruction("beq") == "Branch"
    assert categorize_instruction("jal") == "Control"
    assert categorize_instruction("nop") == "Other"
    assert categorize_instruction("unknown_instr") == "Other"
    print("categorize_instruction tests passed!")

def test_analyze_instruction_mix():
    instructions = [
        0x003100B3,  # add x1, x2, x3
        0x00A10093,  # addi x1, x2, 10
        0x00000073,  # ecall
        0x00000000   # nop
    ]
    stats = analyze_instruction_mix(instructions)
    assert stats["counts"]["ALU"] == 2
    assert stats["counts"]["Control"] == 1
    assert stats["counts"]["Other"] == 1
    print("analyze_instruction_mix tests passed!")





# Run tests
test_get_bits()
test_decode_instruction()
test_get_mnemonic()
test_categorize_instruction()
test_analyze_instruction_mix()