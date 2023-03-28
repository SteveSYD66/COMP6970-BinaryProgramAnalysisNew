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
            self.pe = pefile.PE(executable)
        # If the input file does not exist or is not an executable, throw this error message
        except pefile.PEFormatError:
            print("Error: Unable to read input file '{0}': file does not exist or a truncated file.\n"
                  .format(executable))

    def header_info(self) -> str:
        """
        Header Info

        Prints the header information of the target executable
        :return:
        """
        self.pe.print_info()

    def extract_data(self):
        for section in self.pe.sections:
            if section.Name.decode().strip('\x00') == '.text':
                text_section = section
                break

        if text_section:
            text_data = text_section.get_data()
            # print(text_data)
            return text_data
        else:
            return 0

    def list_data_entries(self):
        print("Magic : " + hex(self.pe.OPTIONAL_HEADER.Magic))
        # Check if it is a 32-bit or 64-bit binary
        if hex(self.pe.OPTIONAL_HEADER.Magic) == '0x10b':
            print("This is a 32-bit binary")
        elif hex(self.pe.OPTIONAL_HEADER.Magic) == '0x20b':
            print("This is a 64-bit binary")
        print("ImageBase : " + hex(self.pe.OPTIONAL_HEADER.ImageBase))
        print("SectionAlignment : " + hex(self.pe.OPTIONAL_HEADER.SectionAlignment))
        print("FileAlignment : " + hex(self.pe.OPTIONAL_HEADER.FileAlignment))
        print("SizeOfImage : " + hex(self.pe.OPTIONAL_HEADER.SizeOfImage))
        print("DllCharacteristics flags : " + hex(self.pe.OPTIONAL_HEADER.DllCharacteristics))
        print("DataDirectory: ")
        print("*" * 50)
        # print name, size and virtualaddress of every DATA_ENTRY in DATA_DIRECTORY
        for entry in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            print(entry.name + "\n|\n|---- Size : " + str(entry.Size) + "\n|\n|---- VirutalAddress : " + hex(
                entry.VirtualAddress) + '\n')
        print("*" * 50)

    def list_sections(self):
        print("Sections Info: \n")
        print("*" * 50)
        for section in self.pe.sections:
            print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(
                section.Misc_VirtualSize) + "\n|\n|---- VirutalAddress : " + hex(
                section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " + hex(
                section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(
                section.PointerToRawData) + "\n|\n|---- Characterisitcs : " + hex(section.Characteristics) + '\n')
        print("*" * 50)
