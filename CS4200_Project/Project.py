#!/usr/bin/env python3
import sys
from collections import defaultdict

MASK32 = 0xFFFFFFFF

# ============================================================
# Utility Functions
# ============================================================
def get_bits(x, hi, lo):
    """Extract bits [hi:lo] inclusive from x."""
    #This function will extract the bits from position lo to hi (inclusive) from the integer x and return the result as an integer. The bits are numbered from 0 (least significant bit) to 31 (most significant bit).
    width = hi - lo + 1
    return (x >> lo) & ((1 << width) - 1)

def decode_instruction(instr):
    """
    Decode a 32-bit RISC-V instruction.
    Returns dict with opcode, funct3, funct7, and instruction type.
    """
    #take in some insturction and returns it in risc-v format
    #the order matters alot!
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
    
    #The input is d from the decode instruction function or some instruction
    #This code is going to return the mnemonic of the instruction based on the opcode, funct3, and funct7 fields. 
    #it decodes the opcode, funct 3 and 7 and goes through a list of tests to determine the instruction type

    op = d["opcode"]
    f3 = d["funct3"]
    f7 = d["funct7"]
    
    if d["instr"] == 0:
        return "nop"
    
    #R-type (0x33)
    #rtype instructions are identified by opcode 0x33 and further differentiated by funct3 and funct7
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
    
    #I-type ALU (0x13)
    #I-type ALU instructions are identified by opcode 0x13 and further differentiated by funct3 and funct7
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
    
    #Load (0x03)
    #load instructions are identified by opcode 0x03 and further differentiated by funct3
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
    
    #Store (0x23)
    #store instructions are identified by opcode 0x23 and further differentiated by funct3
    elif op == 0x23:
        if f3 == 0b000:
            return "sb"
        elif f3 == 0b001:
            return "sh"
        elif f3 == 0b010:
            return "sw"
    
    #Branch (0x63)
    #branch instructions are identified by opcode 0x63 and further differentiated by funct3
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
    
    #JAL (0x6F)
    #jal instruction is identified by opcode 0x6F
    elif op == 0x6F:
        return "jal"
    
    #JALR (0x67)
    #jalr instruction is identified by opcode 0x67
    elif op == 0x67:
        return "jalr"
    
    #LUI (0x37)
    #lui instruction is identified by opcode 0x37
    elif op == 0x37:
        return "lui"
    
    #AUIPC (0x17)
    #auipc instruction is identified by opcode 0x17
    elif op == 0x17:
        return "auipc"
    
    #ECALL/EBREAK (0x73)
    #ecall and ebreak instructions are identified by opcode 0x73 and further differentiated by the full instruction value
    elif op == 0x73:
        if d["instr"] == 0x00000073:
            return "ecall"
        elif d["instr"] == 0x00100073:
            return "ebreak"
    
    #if its some random instruction that doesn't match any of the above patterns, we return "unknown"
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
    # ==========================================================================
    # ======================== instruction sets ================================
    # ==========================================================================
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

    # ==========================================================================
    # ======================= end instruction sets =============================
    # ==========================================================================
    
    #checks if the mnemoic belongs to one of the instruction sets and categorizes it accordingly.

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

# ============================================================
# Analysis Functions
# ============================================================

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
    
    #if counts are not provided, we initialize them to 0 for each category.
    #this ensures that the code doesn't break as it executes
    mnemonic_counts = defaultdict(int)
    category_details = defaultdict(list)
    
    #calculate total number of instructions to compute percentages later on. This is important for understanding the distribution of instruction types in the workload.
    
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

def generate_detailed_report(stats):
    """Generate a detailed text report."""
    lines = []
    
    lines.append("=" * 70)
    lines.append("RISC-V INSTRUCTION MIX ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append("")
    
    # Summary statistics
    lines.append("SUMMARY STATISTICS")
    lines.append("-" * 70)
    lines.append(f"Total instructions analyzed: {stats['total']}")
    lines.append("")
    
    # Instruction mix by category
    lines.append("INSTRUCTION MIX BY CATEGORY")
    lines.append("-" * 70)
    lines.append(f"{'Category':<20} {'Count':<10} {'Percentage':<10}")
    lines.append("-" * 70)
    
    for cat in ["ALU", "Memory", "Branch", "Control", "Other"]:
        count = stats["counts"][cat]
        pct = stats["percentages"][cat]
        lines.append(f"{cat:<20} {count:<10} {pct:>6.2f}%")
    
    lines.append("-" * 70)
    lines.append("")
    
    # Top instructions
    lines.append("TOP 10 MOST FREQUENT INSTRUCTIONS")
    lines.append("-" * 70)
    lines.append(f"{'Instruction':<15} {'Count':<10} {'Percentage':<10}")
    lines.append("-" * 70)
    
    sorted_mnemonics = sorted(stats["mnemonic_counts"].items(), 
                              key=lambda x: x[1], reverse=True)
    
    for i, (mnem, count) in enumerate(sorted_mnemonics[:10]):
        pct = (count / stats["total"]) * 100 if stats["total"] > 0 else 0
        lines.append(f"{mnem:<15} {count:<10} {pct:>6.2f}%")
    
    lines.append("-" * 70)
    lines.append("")
    
    # Workload characterization
    lines.append("WORKLOAD CHARACTERIZATION")
    lines.append("-" * 70)
    
    alu_pct = stats["percentages"]["ALU"]
    mem_pct = stats["percentages"]["Memory"]
    branch_pct = stats["percentages"]["Branch"]
    
    if alu_pct > 50:
        workload_type = "Compute-intensive"
    elif mem_pct > 40:
        workload_type = "Memory-intensive"
    elif branch_pct > 25:
        workload_type = "Control-intensive"
    else:
        workload_type = "Balanced"
    
    lines.append(f"Workload Type: {workload_type}")
    lines.append("")
    
    if alu_pct > 50:
        lines.append("Analysis: High proportion of ALU operations suggests")
        lines.append("computational workload (e.g., numerical processing, algorithms).")
    elif mem_pct > 40:
        lines.append("Analysis: High proportion of memory operations suggests")
        lines.append("data-intensive workload (e.g., data processing, searching).")
    elif branch_pct > 25:
        lines.append("Analysis: High proportion of branches suggests")
        lines.append("control-intensive workload (e.g., decision trees, conditionals).")
    else:
        lines.append("Analysis: Balanced mix of instruction types suggests")
        lines.append("general-purpose workload.")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)

def generate_bar_chart(stats, width=50):
    """Generate ASCII bar chart."""
    lines = []
    
    lines.append("")
    lines.append("INSTRUCTION MIX VISUALIZATION")
    lines.append("-" * 70)
    
    max_pct = max(stats["percentages"].values()) if stats["percentages"] else 1
    
    for cat in ["ALU", "Memory", "Branch", "Control", "Other"]:
        pct = stats["percentages"][cat]
        count = stats["counts"][cat]
        
        # Calculate bar length
        if max_pct > 0:
            bar_len = int((pct / max_pct) * width)
        else:
            bar_len = 0
        
        bar = "█" * bar_len
        
        lines.append(f"{cat:<10} | {bar} {pct:>6.2f}% ({count})")
    
    lines.append("-" * 70)
    
    return "\n".join(lines)

# ============================================================
# File I/O
# ============================================================

def load_instructions_from_file(filepath):
    """Load instructions from hex file."""
    instructions = []
    
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Remove 0x prefix if present
                if line.lower().startswith('0x'):
                    line = line[2:]
                
                try:
                    instr = int(line, 16) & MASK32
                    instructions.append(instr)
                except ValueError:
                    print(f"Warning: Skipping invalid line {line_num}: {line}")
    
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found!")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    return instructions

def save_report(report, filepath):
    """Save report to file."""
    try:
        with open(filepath, 'w') as f:
            f.write(report)
        print(f"Report saved to: {filepath}")
    except Exception as e:
        print(f"Error saving report: {e}")

# ============================================================
# Main Program
# ============================================================

def main():
    """Main program entry point."""
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 instruction_mix_analyzer.py <hex_inst_file>")
        print("\nExample:")
        print("  python3 instruction_mix_analyzer.py hex_inst.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    print("=" * 70)
    print("RISC-V Instruction Mix Analyzer")
    print("=" * 70)
    print(f"\nLoading instructions from: {input_file}")
    
    # Load instructions
    instructions = load_instructions_from_file(input_file)
    
    if not instructions:
        print("Error: No valid instructions found in file!")
        sys.exit(1)
    
    print(f"Loaded {len(instructions)} instructions")
    
    # Analyze instruction mix
    print("\nAnalyzing instruction mix...")
    stats = analyze_instruction_mix(instructions)
    
    # Generate reports
    detailed_report = generate_detailed_report(stats)
    bar_chart = generate_bar_chart(stats)
    
    # Print to console
    print("\n")
    print(detailed_report)
    print(bar_chart)
    
    # Save to file
    output_file = "instruction_mix_report.txt"
    full_report = detailed_report + "\n\n" + bar_chart
    save_report(full_report, output_file)
    
    # Also create CSV output
    csv_file = "instruction_mix_stats.csv"
    save_csv_report(stats, csv_file)
    
    print("\n" + "=" * 70)
    print("Analysis complete!")
    print("=" * 70)

def save_csv_report(stats, filepath):
    """Save statistics as CSV."""
    try:
        with open(filepath, 'w') as f:
            # Header
            f.write("Category,Count,Percentage\n")
            
            # Category data
            for cat in ["ALU", "Memory", "Branch", "Control", "Other"]:
                count = stats["counts"][cat]
                pct = stats["percentages"][cat]
                f.write(f"{cat},{count},{pct:.2f}\n")
            
            f.write("\n")
            f.write("Instruction,Count,Percentage\n")
            
            # Individual instruction data
            sorted_mnemonics = sorted(stats["mnemonic_counts"].items(), 
                                     key=lambda x: x[1], reverse=True)
            
            for mnem, count in sorted_mnemonics:
                pct = (count / stats["total"]) * 100 if stats["total"] > 0 else 0
                f.write(f"{mnem},{count},{pct:.2f}\n")
        
        print(f"CSV data saved to: {filepath}")
    except Exception as e:
        print(f"Error saving CSV: {e}")

if __name__ == "__main__":
    main()