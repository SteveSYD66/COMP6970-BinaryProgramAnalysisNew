from basic_block import BasicBlock


class BasicBlockGenerator:
    def __init__(self):
        self.idx_instr_list = []
        self.return_addr_list = []
        self.unp_instr_addr_list = []    #stores instructions that have not been processed
        self.next_instr_addr_list = []
        self.basic_blocks = []

    def add_basic_block(self, basic_block):
        self.basic_blocks.append(basic_block)

    def delete_basic_block(self, start_instr):
        for basic_block in self.basic_blocks:
            if basic_block.start_instr == start_instr:
                self.basic_blocks.remove(basic_block)
                break

    def split_basic_block(self, bb, jump_to_instr):
        bb_1 = BasicBlock(bb.start_instr)
        bb_2 = BasicBlock(jump_to_instr)

        jump_addr = jump_to_instr.address

        for instr in bb.bb_instr_list:
            if instr.address < jump_addr:
                bb_1.add_instruction(instr)
            else:
                bb_2.add_instruction(instr)

        #add the instr_if_jump as next instr for first basic block
        bb_1.add_bb_next_instrs(jump_to_instr)
        #copy next instr list for og basic block to basic block 2
        bb_2.bb_next_instrs = bb.bb_next_instrs

        self.delete_basic_block(bb)
        self.add_basic_block(bb_1)
        self.add_basic_block(bb_2)
        
    def instr_part_of_basic_block(self, basic_blocks, instr):
        for basic_block in basic_blocks:
            if (instr != basic_block.start_instr and
                instr in basic_block.bb_instr_list):
                #return True
                return basic_block
        #return False
        return None
    
    def basic_block_already_exists(self, basic_blocks, start_instr):
        for bb in basic_blocks:
            if start_instr == bb.start_instr:
                return True
        return False

    def create_idx_instr_list(self, instr_list):
        idx_instr_list = [None] * (max(instr.address for instr in instr_list) + 1)
        for i in range(len(instr_list)):
            instr = instr_list[i]
            addr = instr.address
            idx_instr_list[addr] = instr

        # code below only to save output to file
        f = open("output/idx_instr_list.txt", "w")

        for i in range(0x1000, len(idx_instr_list)):
            instr = idx_instr_list[i]
            if instr is not None:
                mnemonic = instr.mnemonic
                if (mnemonic.startswith("j") or mnemonic.startswith("call")):
                    try:
                        jump_addr = int(instr.op_str, 16)
                    except ValueError:
                        jump_addr = None
                    if jump_addr is not None:
                        string = "0x%04x (%04d): (%02d) %-4s\t%s (%04d)" % (instr.address, instr.address, instr.size, instr.mnemonic, instr.op_str, jump_addr)
                        f.write(string + "\n")
                    else:
                        string = "0x%04x (%04d): (%02d) %-4s\t%s" % (instr.address, instr.address, instr.size, instr.mnemonic, instr.op_str)
                        f.write(string + "\n")
                else:
                    string = "0x%04x (%04d): (%02d) %-4s\t%s" % (instr.address, instr.address, instr.size, instr.mnemonic, instr.op_str)
                    f.write(string + "\n")
            #else:
            #    string = "0x%04x (%04d): (00)" % (i, i)
            #    f.write(string + "\n")

        f.close()

        self.idx_instr_list = idx_instr_list

    def create_basic_blocks(self, instr_list):
        self.create_idx_instr_list(instr_list)

        # self.unp_instr_addr_list = []
        for instr in instr_list:
            self.unp_instr_addr_list.append(instr.address)

        current_bb = BasicBlock(self.idx_instr_list[0x1000])
        next_bb = None
        addr = 0x1000

        # Iterate through the idx instruction list, starting from the first instruction @ 0x1000
        while addr < len(self.idx_instr_list): # or self.next_instr_addr_list[0] is not None:
            instr = self.idx_instr_list[addr]

            if instr is None:
                addr += 1
                continue

            next_instr_addr = addr + instr.size #instr.address + instr.size
            if (next_instr_addr >= 0x1000 and
                next_instr_addr <= len(self.idx_instr_list)):
                next_instr = self.idx_instr_list[next_instr_addr]
            else:
                next_instr = None

            '''
            if instr.address not in self.unp_instr_addr_list:
                addr = next_instr_addr
                continue
            '''
                
            mnemonic = instr.mnemonic
            current_bb.add_instruction(instr)
            if instr.address in self.unp_instr_addr_list:
                self.unp_instr_addr_list.remove(instr.address)

            if (mnemonic.startswith("j") or 
                mnemonic.startswith("call") or 
                mnemonic.startswith("ret")):
                # determine jump to addresses for jump, calls, and returns
                if mnemonic.startswith("j") or mnemonic.startswith("call"):
                    # if op_str is a number, then assign op_str as the jump to address
                    # we ignore instructions such as 'call ebp' since
                    # we have not implemented determining values inside registers
                    try:
                        jump_to_addr = int(instr.op_str, 16)
                    except ValueError:
                        jump_to_addr = None
                elif mnemonic.startswith("ret"):
                    # if return address list contains addresses, then pop it as
                    # the jump to address
                    # otherwise jump to address is none
                    try:
                        return_to_addr = self.return_addr_list.pop()
                        jump_to_addr = return_to_addr
                    except IndexError:
                        return_to_addr = None
                        jump_to_addr = return_to_addr

                # check if jump to address (applies to jumps, calls and returns) is within range
                # if yes, then start next block at the jump to address
                if (jump_to_addr is not None and 
                    jump_to_addr >= 0x1000 and 
                    jump_to_addr <= len(self.idx_instr_list)):
                    
                    jump_to_instr = self.idx_instr_list[jump_to_addr]
                    current_bb.add_bb_next_instrs(jump_to_instr)

                    # conditional jumps are the only instructions to allow
                    # basic blocks to connect to two other basic blocks
                    if (not mnemonic.startswith("jmp") and 
                        mnemonic.startswith("j")):
                        current_bb.add_bb_next_instrs(next_instr)
                        # remember to come back to next instruction after finishing
                        # creating basic blocks from the jump to addresses
                        self.next_instr_addr_list.append(next_instr_addr)
                    
                    if mnemonic.startswith("call"):
                        # remember to return to next instruction after finishing
                        # creating basic blocks from call to addresses
                        self.return_addr_list.append(next_instr_addr)
                    
                    # next_bb = BasicBlock(jump_to_instr)
                    addr = jump_to_addr

                    bb_to_split = self.instr_part_of_basic_block(self.basic_blocks, jump_to_instr)
                    if self.basic_block_already_exists(self.basic_blocks, jump_to_instr):
                        addr = next_instr_addr
                    elif bb_to_split is not None:
                        self.split_basic_block(bb_to_split, jump_to_instr)
                        addr = next_instr_addr
                    pass

                # if jump to address is not within range, 
                # then next block starts at next address
                # and that block has no connections to other blocks
                else:
                    # current_bb.add_bb_next_instrs(next_instr)
                    # next_bb = BasicBlock(next_instr)
                    addr = next_instr_addr

                # if the next instruction to be processed is the next_instr,
                # then there is no need to keep that addr saved in next_instr_addr_list
                if addr == next_instr_addr:
                    if next_instr_addr in self.next_instr_addr_list:
                        self.next_instr_addr_list.remove(next_instr_addr)
                        
                    if self.basic_block_already_exists(self.basic_blocks, next_instr):
                        if self.next_instr_addr_list:
                            addr = self.next_instr_addr_list.pop(0)
                        else:
                            addr = len(self.idx_instr_list)
                            # self.next_instr_addr_list[0] = None

                elif addr == jump_to_addr:
                    if self.basic_block_already_exists(self.basic_blocks, next_instr):
                        self.next_instr_addr_list.remove(next_instr_addr)
                
                self.basic_blocks.append(current_bb)

                if addr < len(self.idx_instr_list):
                    next_bb = BasicBlock(self.idx_instr_list[addr])

                current_bb = next_bb

            # if address does not contain jump, call or return
            # then just move to next instruction
            else:
                addr = next_instr_addr

                if self.basic_block_already_exists(self.basic_blocks, next_instr):
                    if self.next_instr_addr_list:
                        addr = self.next_instr_addr_list.pop(0)
                    else:
                        addr = len(self.idx_instr_list)
                        # self.next_instr_addr_list[0] = None
                    
                    self.basic_blocks.append(current_bb)

                    if addr < len(self.idx_instr_list):
                        next_bb = BasicBlock(self.idx_instr_list[addr])

                    current_bb = next_bb

            # if no more instructions left to add
            if addr >= len(self.idx_instr_list):
                # then then add current block to list of basic blocks
                if not self.basic_block_already_exists(self.basic_blocks, current_bb.start_instr):
                    self.basic_blocks.append(current_bb)
                
                # if unprocessed instructions, then jump to last next address
                if self.next_instr_addr_list:
                    addr = self.next_instr_addr_list.pop(0)
                    next_bb = BasicBlock(self.idx_instr_list[addr])
                    current_bb = next_bb

        print()
        print("Length of indexed instr list: %d" % len(self.idx_instr_list))
        print("Total number of instructions: %d" % len(instr_list))
        print("Total number of unprocessed instructions: %d" % len(self.unp_instr_addr_list))
        print("Unprocessed instruction list: ")
        for i in range(len(self.unp_instr_addr_list)):
            print("0x%04x" % self.unp_instr_addr_list[i])
        print()      

        self.display_basic_blocks(self.basic_blocks)

        return self.basic_blocks
    
    def display_basic_blocks(self, basic_blocks):
        f = open("output/basic_blocks.txt", "w")

        for i, bb in enumerate(basic_blocks):
            f.write(f"Basic Block {i}: {hex(bb.start_instr.address)} - {hex(bb.end_instr.address)}\n")
            f.write(f"\tInstructions: {[hex(instr.address) for instr in bb.bb_instr_list]}\n")
            f.write(f"\tInstructions: {[instr.mnemonic for instr in bb.bb_instr_list]}\n")
            f.write(f"\tNext Instructions: {[hex(instr.address) for instr in bb.bb_next_instrs]}\n")
            f.write("\n")

            #print()
            #print(f"Basic Block {i}: {hex(bb.start_instr.address)} - {hex(bb.end_instr.address)}")
            #print(f"\tInstructions: {[instr.mnemonic for instr in bb.bb_instr_list]}")
            #print(f"\tNext Instructions: {[hex(instr.address) for instr in bb.bb_next_instrs]}")

        f.close()
