from dataclasses import dataclass


@dataclass
class Instruction:
    def __init__(self,
                 address,
                 mnemonic,
                 op_str=None):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str

    def print(self):
        print("0x%x:\t%s\t%s" % (self.address, self.mnemonic, self.op_str))
