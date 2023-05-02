import networkx as nx
import matplotlib.pyplot as plt

from instruction import Instruction
from disassembler import Disassembler
from basic_block import BasicBlock
from bb import BasicBlockGenerator

class CFG():
    def __init__(self):
        self.graph = {}
        self.basic_blocks = []

    def add_node(self, addr):
        """
        Add a node to the control flow graph.

        Parameters:
        - addr (int): the address of the instruction that the node represents
        """
        if addr not in self.graph:
            self.graph[addr] = []


    def add_edge(self, from_addr, to_addr):
        """
        Add an edge between two addresses in the control flow graph.

        Parameters:
        - from_addr (int): the address of the instruction that is the source of the edge
        - to_addr (int): the address of the instruction that is the destination of the edge
        """
        if from_addr not in self.graph:
            self.graph[from_addr] = []
        self.graph[from_addr].append(to_addr)

    def build_cfg(self, basic_blocks):
        """
        Build the control flow graph from a list of basic blocks.

        Parameters:
        - basic_blocks (list of BasicBlock): the basic blocks to build the control flow graph from
        """
        bb_gen = BasicBlockGenerator()

        # Create nodes in the graph for each starting instruction of a basic block
        for bb in basic_blocks:
            self.add_node(bb.start_instr.address)

        # Create edges between basic blocks based on their next_instrs lists
        for bb in basic_blocks:
            for next_instr in bb.bb_next_instrs:
                # If the next instruction is the start of a basic block, add an edge between the end of the current block
                # and the start of the next block
                next_bb = bb_gen.instr_part_of_basic_block(basic_blocks, next_instr)
                if next_bb is not None:
                    self.add_edge(bb.next_instr.address, next_bb.start_instr.address)

        self.display_cfg()

    def display_cfg(self, graph):
        """
        Display the control flow graph using networkx and matplotlib.
        """
        # Create a new networkx graph
        G = nx.DiGraph()

        # Add nodes to the networkx graph
        for addr in self.graph:
            G.add_node(addr)

        # Add edges to the networkx graph
        for from_addr in self.graph:
            for to_addr in graph[from_addr]:
                G.add_edge(from_addr, to_addr)

        # Draw the networkx graph using matplotlib
        pos = nx.spring_layout(G)
        nx.draw_networkx_nodes(G, pos)
        nx.draw_networkx_edges(G, pos)
        nx.draw_networkx_labels(G, pos)
        plt.show()

    