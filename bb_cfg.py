'''
Some parts of this file are helpful if we rewrite this code
but it does not work overall
'''

from disassembler import Disassembler

class BasicBlock:
    def __init__(self, start_address):
        self.start_address = start_address
        self.instructions = []
        self.end_branches = []
        self.fallthrough = None

    def add_instruction(self, instr):
        self.instructions.append(instr)

    def add_end_branch(self, branch_instr):
        self.end_branches.append(branch_instr)

    def set_fallthrough(self, fallthrough):
        self.fallthrough = fallthrough

class BasicBlock_CFG:
    def __init__(self):
        self.basic_blocks = []

    def is_branch_instr(self, instr):
        mnemonic = instr.mnemonic
        return mnemonic.startswith("j") or mnemonic.startswith("call")

    def order_instr_exec_order(self, instr_list):
        visited_instr_list = set()
        ordered_instr_list = []

        # Create a control flow graph by iterating through the instruction list
        control_flow = {}
        for i in range(len(instr_list)):
            # Initialize an empty set of successor indices for each instruction
            control_flow[i] = set()

        # Iterate through the instruction list again
        for i, instr in enumerate(instr_list):
            if self.is_branch_instr(instr):
                # If the instruction is a branch instruction, add the branch target as a successor
                target_addr = instr.op_str
                if target_addr.isdigit():
                    target_addr = int(target_addr, 0)
                    if target_addr < len(instr_list):
                        control_flow[i].add(target_addr)
            else:
                # If the instruction is not a branch instruction, add the next instruction as a successor
                control_flow[i].add(i+1)

        f = open("output/control_flow.txt", "w")
        for i in range(len(instr_list)):
            f.write((f"{i}: {control_flow[i]}") + "\n")
        f.close()

        # Depth-first search to traverse the control flow graph
        def dfs(instr_idx):
            # Mark the current instruction as visited
            visited_instr_list.add(instr_idx)
            # For each successor of the current instruction,
            for succ_idx in control_flow[instr_idx]:
                # If the successor has not been visited yet,
                if succ_idx not in visited_instr_list:
                    # Recursively call the depth-first search function on the successor
                    dfs(succ_idx)
            # Append the current instruction to the ordered instruction list
            ordered_instr_list.append(instr_list[instr_idx])

        # Call the depth-first search function on the first instruction in the instruction list
        dfs(0)

        f = open("output/ordered_instr_list.txt", "w")
        for instr in ordered_instr_list:
            f.write(str(instr) + "\n")
            # print(instr)
        f.close()

        # Return the ordered instruction list
        return ordered_instr_list

    def create_basic_blocks(self, ordered_instr_list):
        # create basic blocks out of a list of instructions
        basic_blocks = [] # initialize an empty list to hold all the basic blocks
        current_block = BasicBlock(ordered_instr_list[0].address) # create a new basic block with the first instruction's address
        basic_blocks.append(current_block) # add the first basic block to the list of basic blocks

        for instr in ordered_instr_list:
            current_block.add_instruction(instr)
            if self.is_branch_instr(instr):
                current_block.add_end_branch(instr) # add the instruction as an end branch for the current basic block
                if instr.address + instr.size < len(ordered_instr_list): # if there is a fallthrough instruction
                    next_instr = ordered_instr_list[instr.address + instr.size] # get the fallthrough instruction
                    fallthrough_block = BasicBlock(next_instr.address) # create a new basic block with the fallthrough instruction's address
                    current_block.set_fallthrough(fallthrough_block) # set the current basic block's fallthrough to the new basic block
                    basic_blocks.append(fallthrough_block) # add the new basic block to the list of basic blocks
                    current_block = fallthrough_block # make the new basic block the current basic block

        f = open("output/basic_blocks.txt", "w")

        for bb in basic_blocks:
            f.write(f"Basic Block @ {hex(bb.start_address)}" + "\n")
            #print(f"Basic Block @ {hex(bb.start_address)}")
            f.write("Instructions:" + "\n")
            #print("Instructions:")
            for instr in bb.instructions:
                f.write(f"\t{instr.mnemonic} {instr.op_str}" + "\n")
                #print(f"\t{instr.mnemonic} {instr.op_str}")
            f.write(f"End branches: {[hex(x.address) for x in bb.end_branches]}" + "\n")
            #print(f"End branches: {[hex(x.address) for x in bb.end_branches]}")
            if bb.fallthrough is not None:
                f.write(f"Fallthrough block: {hex(bb.fallthrough.start_address)}" + "\n")
                #print(f"Fallthrough block: {hex(bb.fallthrough.start_address)}")
            else:
                f.write("Fallthrough block: None" + "\n")
                #print("Fallthrough block: None")
            f.write("\n")    
            #print()

        f.close()

        self.basic_blocks = basic_blocks
