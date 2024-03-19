"""
Program for reading packet headers from a file and computing checksums
"""

import argparse

def main(filename):
    print(f"{filename}")

argparser = argparse.ArgumentParser(description="Read packet headers from a file and compute checksums")

argparser.add_argument('-f', '--filename', required=True, help="Name of the file to read packet headers from")

if __name__ == "__main__":
    filename = argparser.parse_args().filename
    if filename:
        main(filename)
    else:
        print("No filename provided")