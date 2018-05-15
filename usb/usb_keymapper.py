#!/usr/bin/python
from scapy.all import  *

KEY_CODES = {
    2:[' ', ' '],
    4:['a', 'A'],
    5:['b', 'B'],
    6:['c', 'C'],
    7:['d', 'D'],
    8:['e', 'E'],
    9:['f', 'F'],
    10:['g', 'G'],
    11:['h', 'H'],
    12:['i', 'I'],
    13:['j', 'J'],
    14:['k', 'K'],
    15:['l', 'L'],
    16:['m', 'M'],
    17:['n', 'N'],
    18:['o', 'O'],
    19:['p', 'P'],
    20:['q', 'Q'],
    21:['r', 'R'],
    22:['s', 'S'],
    23:['t', 'T'],
    24:['u', 'U'],
    25:['v', 'V'],
    26:['w', 'W'],
    27:['x', 'X'],
    28:['y', 'Y'],
    29:['z', 'Z'],
    30:['1', '!'],
    31:['2', '@'],
    32:['3', '#'],
    33:['4', '$'],
    34:['5', '%'],
    35:['6', '^'],
    36:['7', '&'],
    37:['8', '*'],
    38:['9', '('],
    39:['0', ')'],
    40:['\n','\n'],
    44:[' ', ' '],
    45:['-', '_'],
    46:['=', '+'],
    47:['[', '{'],
    48:[']', '}'],
    49:['\\', '|'],
    50:['#','~'],
    51:[';', ':'],
    52:['\'', '"'],
    54:[',', '<'],
    56:['/', '?'],
    55:['.', '>'],
    43:['\t','\t'],
    79:['RIGHT', 'RIGHT'],
    80:['LEFT', 'LEFT']
}

def main():
    packets = rdpcap("FILE") 
    pos = 0
    words = []

    for packet in packets:
        hid_report = packet.load[-8:]
        shift = 1 if ord(hid_report[0]) > 0 else 0
        key = ord(hid_report[2])
        
        try:
            if key == 0:
                continue
            elif KEY_CODES[key][shift] == "RIGHT":
                pos += 1
            elif KEY_CODES[key][shift] == "LEFT":
                pos -= 1
            else:
                if pos == 0:
                    words.append(KEY_CODES[key][shift])
                else:
                    current_pos = len(words)
                    words.insert(current_pos + pos, KEY_CODES[key][shift])
        except: 
            #print("key: {}, shift: {}".format(key, shift))
            continue
    print(''.join(words))

if __name__ == "__main__":
    main()
