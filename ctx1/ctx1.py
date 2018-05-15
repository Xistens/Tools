#!/usr/bin/env python3
"""
https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2014/january/good-fun-with-bad-crypto/
"""
import re, sys
import argparse
import ctx1encode

def decrypt(ct):
    ct = re.sub('[^A-P]', '', ct.upper())

    pt = ''
    last = 0
    try:
        for i in range(0, len(ct), 4):
            pc = dec_letter(ct[i:i+4], last) 
            pt += pc
            last ^= ord(pc)
    except IndexError:
        raise IndexError("Not valid ctx1?")

    return pt

def dec_letter(ct, last=0):
    c = (ord(ct[2]) - 1) & 0x0f
    d = (ord(ct[3]) - 1) & 0x0f

    x = c*16+d

    pc = chr(x^last)

    return pc

def run(passwd, encode=False, file=False):
    """ run() is a generator, and yields results from the work queue """
    if file:
        try:
            with open(file, "r") as fh:
                for line in fh:
                    if not encode:
                        yield (line, decrypt(line))
                    else:
                        yield (line, ctx1encode.encrypt(line.strip()))
        except IOError:
            raise IOError("Failed reading file: {0}".format(args.file))
    else:
        if passwd:
            if not encode:
                yield (passwd, decrypt(passwd))
            else:
                yield (passwd, ctx1encode.encrypt(passwd))
        else:
            raise NameError("Encoded password missing")

def main(args, output=False):
    try:
        for (line, result) in run(args.passwd, args.encode, args.file):
            line = line.rstrip()
            if output:
                output.write(line + ":" + result + "\n")
                output.flush()
            else:
                print(line + ":" + result)
    except KeyboardInterrupt:
        print("User aborted")
    finally:
        if output:
            output.close()

def parse_args(args):
    """ Create the arguments """
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", dest="passwd", help="Single encoded password to decode")
    parser.add_argument("-P", dest="file", help="Load several encoded passwords from file")
    parser.add_argument("-o", dest="output", help="Write decoded password to FILE instead of stdout", default=False)
    parser.add_argument("-e", action="store_true", dest="encode", help="ctx1 encode password", default=False)

    if len(sys.argv) < 2:
        parser.print_help()
        exit(0)

    argsp = parser.parse_args(args)
    if not (argsp.passwd or argsp.file):
        parser.print_help()
    
    return argsp

if __name__ == "__main__":
    options = parse_args(sys.argv[1:])

    output = False
    if options.output:
        try:
            output = open(options.output, "w")
        except IOError:
            raise IOError("Failed writing to file: {0}".format(options.outout))
    
    main(options, output)
    
