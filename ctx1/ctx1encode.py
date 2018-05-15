#!/usr/bin/env python3
import sys 

def encrypt(pt):
    ct = ''
    last = 0
    for ch in pt:
        ct += enc_letter(ch, last)
        last ^= ord(ch)

    return ct

def enc_letter(ch, last=0):
    c = ord(ch) ^ last
    h = c // 16 # high nybble
    l = c % 16 # low nybble

    a = h ^ 0x0A 
    b = l ^ 0x05 
    c = h
    d = l

    ach = chr(a+0x41)
    bch = chr(b+0x41)
    cch = chr(c+0x41)
    dch = chr(d+0x41)

    return "%s%s%s%s" % (ach, bch, cch, dch)