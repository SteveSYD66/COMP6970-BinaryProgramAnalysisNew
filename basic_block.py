class BasicBlock:
    def __init__(self, start_instr):
        self.start_instr = start_instr
        self.end_instr = None
        self.bb_instr_list = []
        self.bb_next_instrs = []

    def add_instruction(self, instr):
        self.bb_instr_list.append(instr)
        self.end_instr = instr

    def add_bb_next_instrs(self, next_instr):
        self.bb_next_instrs.append(next_instr)
