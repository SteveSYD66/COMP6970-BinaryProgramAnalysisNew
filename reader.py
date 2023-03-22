# Python imports
import pefile

class Reader:
    def __init__(self,
                 executable: str):
        """
        __init__

        Initiate the reader
        :param executable: The string containing path to target executable
        """

        # Use pefile to parse target executable
        try:
            pe = pefile.PE(executable)
        # If the input file does not exist or is not an executable, throw this error message
        except pefile.PEFormatError:
            print("Error: Unable to read input file '{0}': file does not exist or a truncated file.\n"
                  .format(executable))
