"""
This module contains a function to turn a bytes object into a randomart
string.
see: http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
for a description of randomart

Basically the only function in this file that is useful to import is 
the last one, 'randomart'. So the recommended usage is:
from randomart import randomart
"""

# There is a character code for how many times a particular square has been hit
valChars = ' .o+=*BOX@%&#/^'

def get8bits(num):
    """
    Turn a number into an length-8 bit string of 0s and 1s
    """
    # num is an int
    bString = bin(num)[2:]
    bOut = '0'*(8-len(bString)) + bString
    return bOut

def group2bits(bitString):
    """
    Turn a string of 0s and 1s, group into pairs of two characters and 
    return a list with these pairs
    """
    assert len(bitString)%2 == 0, \
        "The length of the bitstring must be an even number"
    iterList = [iter(bitString)]*2
    bitPairList = [''.join(item) for item in zip(*iterList)]
    return bitPairList

def bytes2bitpairs(bStr):
    """
    Takes a bytes object and returns a list of bit pairs. Bytes are 
    read left-to-right, but within a byte, bitpairs are read 
    right-to-left
    """
    list_of_bit_pairs = [group2bits(get8bits(item)) for item in bStr]
    pair_list = [item for 
        sublist in list_of_bit_pairs for 
        item in sublist[-1::-1]]
    return pair_list

# dims[0] x dims[1] grid (columns x rows)
def gen_xy_positions(bit_pair_string, dims=(17, 9)):
    """
    Takes a list of bit pairs and returns a list of positions in the 
    path.
    """
    pairPositions = [(dims[0]//2, dims[1]//2)]
    for pair in bit_pair_string:
        dx = -1 if pair[-1] == '0' else 1
        dy = -1 if pair[0] == '0' else 1
        newX = pairPositions[-1][0] + dx
        newX = max(0, newX)
        newX = min(dims[0]-1, newX)
        newY = pairPositions[-1][1] + dy
        newY = max(0, newY)
        newY = min(dims[1]-1, newY)
        pairPositions.append((newX, newY))
    return pairPositions

def coord_pair_to_position(cpair, dims=(17, 9)):
    """
    cpair should be a length-2 tuple with (x, y) coordinates.
    This ordered pair gets converted to a single number.  If the rows 
    and 17 columns are broken up row-by-row and appended, then the 
    position number is the index of the spot along this single array.
    """
    pos = cpair[1]*dims[0] + cpair[0]
    return pos

def gen_header_footer_line(label, poz='header', dims=(17, 9)):
    pre_space = (dims[0]-min(dims[0]-2,len(label))-2)//2
    post_space = (dims[0]-min(dims[0]-2,len(label))-2) - pre_space
    tl = chr(0x250f)
    tr = chr(0x2513)
    bl = chr(0x2517)
    br = chr(0x251b)
    hline = chr(0x2501)
    if poz == 'header':
        lcor = tl
        rcor = tr
    elif poz == 'footer':
        lcor = bl
        rcor = br
    else:
        raise ValueError("Cannot interpret kwarg 'poz'")
    line_text = lcor + hline*pre_space + '[' + label[:(dims[0]-2)] + ']' + \
        hline*post_space + rcor
    return line_text

def randomart(bStr, keyname='RSA 4096', hashname='SHA256', dims=(17, 9)):
    """
    Takes a bytes object ('bStr') and gives random art
    dims are the dimensions of the board in a tuple: (columns, rows)
       both rows and columns must be odd ints.
    """
    assert (dims[0] % 2) == 1, "Number of columns must be odd"
    assert (dims[1] % 2) == 1, "Number of rows must be odd"
    bitPairs = bytes2bitpairs(bStr)
    xyPosList = gen_xy_positions(bitPairs, dims=dims)
    posnumList = [coord_pair_to_position(pair, dims=dims) for 
        pair in xyPosList]
    boardPosList = [0]*dims[0]*dims[1]
    for pos in posnumList:
        boardPosList[pos] += 1
    boardPosList = [min(pos,len(valChars)-1) for 
        pos in boardPosList] # truncate the list
    boardCharList = [valChars[pos] for pos in boardPosList]
    startPos = dims[0]*(dims[1]//2) + (dims[0]//2)
    boardCharList[startPos] = 'S'
    boardCharList[posnumList[-1]] = 'E'
    boardCharStr = ''.join(boardCharList)
    vline = chr(0x2503)
    # split up the str in chunks of dims[0] (i.e. into rows)
    iterList = [iter(boardCharStr)]*dims[0]
    boardCharStrChunks = [''.join(item) for item in zip(*iterList)]
    dispCharChunks = [vline + item + vline for item in boardCharStrChunks]
    headerText = gen_header_footer_line(keyname, poz='header', dims=dims)
    footerText = gen_header_footer_line(hashname, poz='footer', dims=dims)
    dispCharChunks = [headerText] + dispCharChunks + [footerText]
    displayText = '\n'.join(dispCharChunks)
    return displayText




