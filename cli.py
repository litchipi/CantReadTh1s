#!/usr/bin/env python3
#-*-encoding:utf-8*-

import sys
import argparse
from cantreadth1s import CantReadThis, VERSION
from cantreadth1s.compression import CompressionWrapper


def print_version():
    print("CantReadThis version " + VERSION)
    print("Written by litchipi under GPLv3 license")
    print("litchi.pi@protonmail.com\t@LitchiPi\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--outfile', '-o', type=str, help='Where to save the recovered data')
    parser.add_argument('--display-only', '-d', help='Print result to stdout and do not write to file', action="store_true")
    parser.add_argument('--info', '-i', type=str, help='Information about the file, its content or an indication of the password')
    parser.add_argument('--security-level', '-s', type=int,
            help='Security level to use, changes the parameters of the password derivation function. Can go to infinite, default is 1.', default=1)
    parser.add_argument('--compression-algorithm', '-c', help="The compression algorithm to use to process the data", type=str, choices=CompressionWrapper.COMPRESSION_ALGORITHMS_AVAILABLE, default=CompressionWrapper.DEFAULT_COMPRESSION_ALGORITHM)
    parser.add_argument('--verbose', '-v', help="Display informations about the file and the process", action="store_true")
    parser.add_argument('--password', '-p', help='Password to use', type=str)
    parser.add_argument("--version", "-V", help="Prints the current version", action="store_true")
    parser.add_argument("--debug", "-D", help="Enable debug outputs", action="store_true")
    parser.add_argument('fname', metavar='filename', type=str, help="The file you want to process/recover", nargs="*")

    args = parser.parse_args()
    if args.version:
        print_version()
        return 0
    elif args.fname is None:
        print_version()
        parser.print_help()
        return 1

    cr = CantReadThis(**args.__dict__)
    success, res = cr.handle_file(args.fname)
    if args.debug:
        print("Success ? ", success)
    if not success:
        print(res)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
