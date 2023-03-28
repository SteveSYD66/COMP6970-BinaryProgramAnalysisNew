# Python imports
import pefile
import argparse

# Project imports
from reader import Reader
from disassembler import Disassembler
from cfg import CFG

code = b"\x48\x8d\x3d\x2b\x00\x00\x00\xe8\x00\x00\x00\x00\x48\xb8\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x48\x89\xc7\x48\xb8\x72\x6c\x64\x21\x0a\x00\x00\x00\x48\x89\xc6\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\x48\x31\xc0\x48\x83\xec\x08\x48\xb8\x01\x00\x00\x00\x00\x00\x00\x00\x48\x89\xe7\xb8\x00\x00\x00\x00\x48\x83\xc0\x01\x0f\x05\x48\x31\xd2\x31\xc0\xb8\x3c\x00\x00\x00\x0f\x05"


def main():
    """
    Main Method

    Launch the disassembler from this method
    :return: Currently none
    """

    print("-------------------------------------------\n"
          "COMP 6970 Binary Program Analysis Project\n"
          "Project: Disassembler\n"
          "Authors:\n"
          "Mukarram Ali Faridi\n"
          "Yuantai Pan\n"
          "-------------------------------------------\n")
    print("testing with a test file \"hello.exe\t\n")

    file_reader = Reader("test_code/hello.exe")
    # file_reader.header_info()
    text = file_reader.extract_data()
    with open("test_code/hello.exe", "rb") as f:
        data = f.read()
    disassembler = Disassembler()
    print("Disassembling with capstone:\n")
    disassembler.disassemble_capstone(text)
    print("Disassembling now...\n")
    disassembler.disassemble(text)
    # cfg = CFG()
    # cfg.make_graph(code)
    # file_reader.list_sections()


if __name__ == "__main__":
    main()
