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

        # just printing these for now to test
        for byte in hex_byte_array:
            print(byte)

def main(filename):
    packet_data = process_packet_file(filename)

if __name__ == "__main__":
    filename = argparser.parse_args().filename
    if filename:
        main(filename)
    else:
        print("No filename provided")