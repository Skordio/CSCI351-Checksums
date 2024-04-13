"""
Program for reading packet headers from a file and computing checksums
"""

import argparse

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")


def process_packet_file(filename):
    with open(filename, 'r') as packet_file:
        # line with + and - signs
        packet_file.readline()

        # line with date info and connection type
        packet_file.readline()

        # line with hex info
        hex_line = packet_file.readline()

        hex_byte_array = hex_line.split('|')
        
        hex_byte_array = [byte for byte in hex_byte_array if len(byte) == 2]

        # just printing these for now to test
        string = ''
        for byte in hex_byte_array:
            string += byte
            
        print(string)
            
def check_file_exists(filename):
    try:
        with open(filename, 'r') as file:
            return True
    except FileNotFoundError:
        return False

def main(filename):
    packet_data = process_packet_file(filename)

if __name__ == "__main__":
    filename = argparser.parse_args().filename
        
        
    if not filename:
        print("No filename provided")
        
    if not check_file_exists(filename):
        print("File does not exist")
        
    main(filename)