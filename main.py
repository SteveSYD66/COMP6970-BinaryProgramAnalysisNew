# Python imports
import pefile
import argparse

# Project imports
from reader import Reader

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
    print("testing with a test file \"text.txt\t\n")

    file_reader = Reader("test_code/text.txt")


if __name__ == "__main__":
    main()
