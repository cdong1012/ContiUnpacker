import speakeasy
import logging
import pefile
import argparse
def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_dll')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.DEBUG)

    return logger

class ContiUnpacker(speakeasy.Speakeasy):
    def __init__(self, input_path, output_path):
        super(ContiUnpacker, self).__init__(debug = False, logger=get_logger())
        self.input_path = input_path
        self.output_path = output_path

    def dump(self):
        image = self.get_address_map(self.dump_addr)
        print("[*] Dump Address:", hex(image.get_base()))
        print("[*] Dump Address:", hex(image.get_size()))
        self.pe_data = self.mem_read(image.get_base(), image.get_size())

        if self.is_pe(self.pe_data):
            print("[*] Found valid PE file")
            self.fix_IAT()


    def fix_IAT(self):
        pe = pefile.PE(data=self.pe_data)
        for i in range(len(pe.sections)):
            pe.sections[i].PointerToRawData = pe.sections[i].VirtualAddress
            pe.sections[i].Misc_VirtualSize = pe.sections[i].SizeOfRawData if i + 1 == len(pe.sections) else pe.sections[i + 1].VirtualAddress - pe.sections[i].VirtualAddress

        pe.write(self.output_path)

    def hookVirtualAlloc(self, emu, api_name, func, params):
        if params[0] == 0x400000 or params[0] == 0:
            params[1] = 0x34000
        return func(params)

    def hookVirtualProtect(self, emu, api_name, func, params):
        self.dump_addr = params[0] - 0x1000
        print("[*] VirtualProtect CALLED!")
        self.stop()
        self.dump()

    def run(self):
        self.module = self.load_module(self.input_path)
        print("fuck")
        self.add_api_hook(self.hookVirtualAlloc, 'kernel32', 'VirtualAlloc')
        self.add_api_hook(self.hookVirtualProtect, 'kernel32', 'VirtualProtect')
        self.run_module(self.module, all_entrypoints=False)

def main(args):
    # 
    unpacker = ContiUnpacker(args.file, args.outfile)
    unpacker.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Conti Unpacker unpacker')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of UPX file to unpack')
    parser.add_argument('-o', '--outfile', action='store', dest='outfile',
                        required=True, help='Path to save unpacked file')
    args = parser.parse_args()
    main(args)