import pydot
import capstone


class CFG:
    def __init__(self):
        self.graph = pydot.Dot(graph_type='digraph')
        self.nodes = {}
    def make_graph(self, asm_code):

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        for instr in md.disasm(code, 0x1000):
            node = pydot.Node(str(instr.address), label=str(instr))
            self.nodes[instr.address] = node
            self.graph.add_node(node)
            if instr.address > 0 and instr.address-1 in self.nodes:
                self.graph.add_edge(pydot.Edge(self.nodes[instr.address-1], node))
            if instr.address+1 in self.nodes:
                self.graph.add_edge(pydot.Edge(node, self.nodes[instr.address+1]))

        self.graph.write_png('cfg.png')