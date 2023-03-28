# Python imports
from capstone import *

# Project imports
from instruction import Instruction

INSTR_MAX = 15


class Disassembler:
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.instr_list = []

    def disassemble(self, code: bytes):
        """
        disassemble

        disassemble the given binary code with linear sweep algorithm
        the disassembled output is appended into the instr_list
        :param code: input binary code in bytes format
        :return: gives no return, the output is stored in instr_list
        """
        # initialize byte offset and default address
        offset = 0
        address = 0x1000

        terminate = False
        # use a while loop to sweep through the text section of the program
        while offset < len(code) and not terminate:
            """
            The algorithm will start with scanning a byte of size 1, the scanned code will be fed into Capstone's
            disasm() function
            If the output is not a valid instruction, repeat the process with the input data's size increased by 1 until
            a valid output is detected
            """
            size = 1
            # slice a section of code for disassembling
            target = code[offset:size + offset]
            not_disassembled = True
            # use the second output to generate a valid output
            while not_disassembled:
                # if size > INSTR_MAX:
                    # not_disassembled = False
                    # break
                try:
                    # this line of instruction can be potentially replaced with a self-made disasm() function
                    output_instr = list(self.md.disasm(target, address))
                    # check if there is a valid output
                    if len(output_instr) == 1:
                        not_disassembled = False
                    else:
                        size += 1
                        if size > INSTR_MAX:
                            terminate = True
                            break
                        target = code[offset:size + offset]
                # exception handling
                except CsError:
                    size += 1
                    target = code[offset:size + offset]
            # append disassembled instruction into instruction list
            if len(output_instr) > 0:
                for i in output_instr:
                    new_instr = Instruction(i.address, i.mnemonic, i.op_str)
                    self.instr_list.append(i)
                    new_instr.print()
                offset += size
                address += size
            if address == 0x3b8f:
                flag = True

    def disassemble_capstone(self, code_cap: bytes):
        """
        disassemble_capstone

        disassemble the given code fully utilizing capstone disasm() function
        :param code_cap: input binary code
        :return: print of disassembled code
        """
        disasm = self.md.disasm(code_cap, 0x1000)
        for i in disasm:
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        return disasm

    def predict(self, code_prdt: bytes):
        length = 0
        # check for single byte instructions
        if code_prdt[0] == 0x90:
            length = 1
            return length
        else:
            # Check for opcode length
            if code_prdt[0] == 0x0f:
                length += 1
                if code_prdt[1] == 0x38 or code_prdt[1] == 0x3a:
                    length += 1
            length += 1
            length += 2
            if len(code_prdt) < length:
                length = len(code_prdt)
            return length
