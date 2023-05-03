# Python imports
import pefile
import argparse

# Project imports
from reader import Reader
from disassembler import Disassembler
from bb import BasicBlockGenerator
from cfg import CFG
from bb_chatgpt import BasicBlockExplorer

code = b"\x48\x8d\x3d\x2b\x00\x00\x00\xe8\x00\x00\x00\x00\x48\xb8\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x48\x89\xc7\x48\xb8\x72\x6c\x64\x21\x0a\x00\x00\x00\x48\x89\xc6\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\x48\x31\xc0\x48\x83\xec\x08\x48\xb8\x01\x00\x00\x00\x00\x00\x00\x00\x48\x89\xe7\xb8\x00\x00\x00\x00\x48\x83\xc0\x01\x0f\x05\x48\x31\xd2\x31\xc0\xb8\x3c\x00\x00\x00\x0f\x05"


def main():
    """
    Main Method

    Launch the disassembler from this method
    :return: Currently none
    """
    filename = "testing/test.exe"

    print("-------------------------------------------\n"
          "COMP 6970 Binary Program Analysis Projects\n"
          "Project: Disassembler\n"
          "Authors:\n"
          "Yuantai Pan\n"
          "Mukarram Ali Faridi\n"
          "-------------------------------------------\n")
    print("testing with a test file \"" + filename + "\"")

    file_reader = Reader(filename)
    file_reader.header_info()
    text = file_reader.extract_data()
    disassembler = Disassembler()
    # print("\nDisassembling with capstone:\n")
    disassembler.disassemble_capstone(text)
    # print("\nDisassembling using linear sweep:\n")
    disassembler.disassemble(text)
    # file_reader.list_data_entries()
    bb = BasicBlockGenerator()
    bb.create_basic_blocks(disassembler.instr_list)
    # cfg = CFG()
    # cfg.display_cfg(bb.basic_blocks)
    chatGPT = BasicBlockExplorer()
    bb_index = chatGPT.request_basic_block_index()
    chatGPT.explain_basic_block(bb_index, bb.basic_blocks)

if __name__ == "__main__":
    main()
