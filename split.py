#!/usr/bin/python3
import sys
import os
import argparse

def parse_args(args):
    """ Create the arguments """
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="infile", help="File to split")
    parser.add_argument("-s", dest="maxFileSize", help="Filesize in kb (default 50000kb)", default=100000)

    if len(sys.argv) < 2:
        parser.print_help()
        #exit(0)
    
    argsp = parser.parse_args(args)
    if not argsp.infile:
        parser.print_help()
    return argsp

def new_file(infile, id=""):
    """
    Creates a new file based on the infile
    New name = infile + filenumber + infile's extension
    """
    if not infile:
        raise ValueError("Infile in new_file() cannot be empty.")
    filename, fileExtension = os.path.splitext(infile)
    path = os.path.dirname(os.path.realpath(__file__))
    newName = "{}{}{}".format(filename, str(id), fileExtension)
    try:
        file = open(os.path.join(path, newName), "w", encoding="UTF-8")
    except IOError:
        raise IOError("Failed on creating new file '{0}'".format(newName))
    return file

def getLines(infile):
    """
    getLines() is a generator and yields a line from the work queue
    """
    if not infile:
        raise ValueError("Infile in getLines() cannot be empty.")
    try:
        with open(infile, "rb") as fh:
            for line in fh:
                yield line.decode(encoding="UTF-8", errors="replace")
    except IOError:
        raise IOError("Failed reading file {0}".format(infile))

def getFileSize(file):
    return os.path.getsize(file) / 1024.0

def split(infile, maxFileSize=100000):
    """
    This function gets a line from getLines() generator and 
    writes it to the output file.

    If buffer size is >= maxfilesize then write buffer to output
    and create a new output file, then continue until done.
    """
    # Convert kibibyte to bytes
    maxFileSize = int(maxFileSize) * 1024
    output = new_file(infile, 0)

    fileNumber = 0
    size = 0
    for line in getLines(infile):
        output.write(line)
        size += sys.getsizeof(line)

        if size >= maxFileSize:
            output.close()
            fileNumber += 1
            size = 0
            print("[+] Saving file {0} with total size of {1:.3f} kb".format(output.name, getFileSize(output.name)))
            output = new_file(infile, fileNumber)
            
    output.close()
    print("[+] Saving file {0} with total size of {1:.3f} kb".format(output.name, getFileSize(output.name)))

    print("\n[+] Done.")

if __name__ == "__main__":
    options = parse_args(sys.argv[1:])

    if os.path.isfile(options.infile):
        split(options.infile, options.maxFileSize)
    else:
        raise FileNotFoundError("Cannot find the file {}".format(options.infile))
