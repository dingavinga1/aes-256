import sys
from bitstring import BitArray as bits
import copy
import hashlib
from array import array
import os
from tqdm import tqdm

SBOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

InvSBOX = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

coefficients=[
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5
]

##########################################
############### KEY EXPANSION ############
##########################################

def sthToBin(sth):
    return bits('0b'+bin(sth)[2:].rjust(8, '0'))

def addRC(w, round):
    w=copy.deepcopy(w)
    w[0]^=sthToBin(coefficients[round-1])
    return w

def substitute(w, inverse=False):
    w=copy.deepcopy(w)
    for i in range(len(w)):
        if inverse==False:
            w[i]=sthToBin(SBOX[(w[i][:4]).uint][(w[i][4:]).uint])
        else:
            w[i]=sthToBin(InvSBOX[(w[i][:4]).uint][(w[i][4:]).uint])
    return w           

def roll(w, inverse=False):
    w=copy.deepcopy(w)
    if inverse==False:
        w.append(w[0])
        w.pop(0)
    else:
        w.insert(0, w[-1])
        w.pop()
    return w

def g(w, round):
    return addRC(substitute(roll(w)), round) 

def qXOR(w1, w2):
    w1=copy.deepcopy(w1)
    for i in range(len(w1)):
        w1[i]^=w2[i]
    return w1

def keyExpansion(slicedKey):
    for i in range(14//2):
        first=qXOR(g(slicedKey[-1], i+1), slicedKey[-8])
        slicedKey.append(first)
        for j in range(7):
            if j==3:
                slicedKey.append(qXOR(substitute(slicedKey[-1]), slicedKey[-8]))
            else:
                slicedKey.append(qXOR(slicedKey[-1], slicedKey[-8]))

##########################################
################# ROUND STEPS ############
##########################################

def addRoundKey(roundKey, plainText):
    return [qXOR(roundKey[i], plainText[i]) for i in range(len(roundKey))]

def multCheck(first, second):
    p=0x00
    while second:
        if second&1:
            p^=first
        first<<=1
        if first&0x100:
            first^=0x1b
        second>>=1
    return p&0xff

galois_m_2=array('i', [multCheck(x, 2) for x in range(256)])
galois_m_3=array('i', [multCheck(x, 3) for x in range(256)])
galois_m_9=array('i', [multCheck(x, 9) for x in range(256)])
galois_m_11=array('i', [multCheck(x, 11) for x in range(256)])
galois_m_13=array('i', [multCheck(x, 13) for x in range(256)])
galois_m_14=array('i', [multCheck(x, 14) for x in range(256)])

def mixColumns(plainText, inverse=False):
    result=copy.deepcopy(plainText) 
    if inverse==False:  
        idTwo=galois_m_2
        idThree=galois_m_3
        for i in range(4):
            result[0][i]=sthToBin(idTwo[plainText[0][i].uint] ^ plainText[3][i].uint ^ plainText[2][i].uint ^ idThree[plainText[1][i].uint])
            result[1][i]=sthToBin(idTwo[plainText[1][i].uint] ^ plainText[0][i].uint ^ plainText[3][i].uint ^ idThree[plainText[2][i].uint])
            result[2][i]=sthToBin(idTwo[plainText[2][i].uint] ^ plainText[1][i].uint ^ plainText[0][i].uint ^ idThree[plainText[3][i].uint])
            result[3][i]=sthToBin(idTwo[plainText[3][i].uint] ^ plainText[2][i].uint ^ plainText[1][i].uint ^ idThree[plainText[0][i].uint])
    else:
        idNine=galois_m_9
        idEleven=galois_m_11
        idThirteen=galois_m_13
        idFourteen=galois_m_14
        for i in range(4):
            result[0][i]=sthToBin(idNine[plainText[3][i].uint] ^ idEleven[plainText[1][i].uint] ^ idThirteen[plainText[2][i].uint] ^ idFourteen[plainText[0][i].uint])
            result[1][i]=sthToBin(idNine[plainText[0][i].uint] ^ idEleven[plainText[2][i].uint] ^ idThirteen[plainText[3][i].uint] ^ idFourteen[plainText[1][i].uint])
            result[2][i]=sthToBin(idNine[plainText[1][i].uint] ^ idEleven[plainText[3][i].uint] ^ idThirteen[plainText[0][i].uint] ^ idFourteen[plainText[2][i].uint])
            result[3][i]=sthToBin(idNine[plainText[2][i].uint] ^ idEleven[plainText[0][i].uint] ^ idThirteen[plainText[1][i].uint] ^ idFourteen[plainText[3][i].uint])
    
    return result

def encryption(slicedKey, plainText):
    cipherText=[]
    for i in range(4):
        cipherText.append([])
        for j in range(4):
            cipherText[i].append(plainText[j][i])
    usableKey=[]
    for i in range(4):
        usableKey.append([])
        for j in range(4):
            usableKey[i].append(slicedKey[j][i])
    cipherText=addRoundKey(usableKey, cipherText)

    for k in range(14):
        usableKey=[]
        for i in range(4):
            usableKey.append([])
            for j in range(4):
                usableKey[i].append(slicedKey[(4*(k+1))+j][i])
        
        for i in range(len(cipherText)):
            cipherText[i]=substitute(cipherText[i])
        for i in range(len(cipherText)):
            for _ in range(i):
                cipherText[i]=roll(cipherText[i])
        if k!=13:
            cipherText=mixColumns(cipherText)
        
        cipherText=addRoundKey(usableKey,cipherText) 

    for i in range(4):
        for j in range(4):
            plainText[i][j]=cipherText[j][i]     

    return plainText

def decryption(slicedKey, plainText):
    newKey=[]
    for i in range(len(slicedKey)-4, -1, -4):
        for j in range(4):
            newKey.append(slicedKey[i+j])
    slicedKey=newKey

    cipherText=[]
    for i in range(4):
        cipherText.append([])
        for j in range(4):
            cipherText[i].append(plainText[j][i])
    usableKey=[]
    for i in range(4):
        usableKey.append([])
        for j in range(4):
            usableKey[i].append(slicedKey[j][i])
    cipherText=addRoundKey(usableKey, cipherText)

    for k in range(14):
        usableKey=[]
        for i in range(4):
            usableKey.append([])
            for j in range(4):
                usableKey[i].append(slicedKey[(4*(k+1))+j][i])
        
        for i in range(len(cipherText)):
            for _ in range(i):
                cipherText[i]=roll(cipherText[i], inverse=True)

        for i in range(len(cipherText)):
            cipherText[i]=substitute(cipherText[i], inverse=True)
        
        cipherText=addRoundKey(usableKey,cipherText) 

        if k!=13:
            cipherText=mixColumns(cipherText, inverse=True)

    for i in range(4):
        for j in range(4):
            plainText[i][j]=cipherText[j][i]     

    return plainText


##########################################
###### DRIVER AND KEY SLICING ############
##########################################

def sliceInitialKey(key):
    key=key.split(" ")
    w=[]
    for i in range(8):
        w.append([])
        for j in range(4):
            w[-1].append(bits('0x'+key[(4*i)+j]))
    return w

def padding(curr):
    curr=curr+('\x00'*(16-len(curr))).encode()
    textArr=bits(curr)
    w=[]
    for i in range(4):
        w.append([])
        for j in range(4):
            w[-1].append(textArr[(32*i)+(j*8):((32*i)+(8*j))+8])
    return w

def ecb(ifilename, ofilename, key, encrypt=True):
    if encrypt:
        print("Encryption Progress")
    else:
        print("Decryption Progress")
    fileSize=os.path.getsize(ifilename)
    with open(ifilename, "rb") as ifile, open(ofilename, "wb") as ofile:
        #while True:
        for i in tqdm(range(fileSize//16)):
            content=ifile.read(16)
            if not content:
                break

            pt=padding(content)
            if encrypt:
                ct=encryption(key, pt)
            else:
                ct=decryption(key, pt)
            #print(ct)

            for i in range(len(ct)):
                for j in range(4):
                    ofile.write(bytes((int(ct[i][j].hex, 16),)))
    return None


def _start():
    help='''
        Encrypt/Decrypt files using 256 bit AES\n
        Usage: aes256.py [raw_key/short_key] [<key_file>/<paraphrase>] [encrypt/decrypt] <path to input file> <path to output file>\n
        raw_key: Use exact 256 bit key (Should be provided as space-separated hex dump in key_file)
        short_key: Use sha256 to convert secret paraphrase into 256 bit key
    '''
    if len(sys.argv)<6 or sys.argv[1]=='help':
        print(help)
        exit()

    if len(sys.argv)!=6:
        print("Invalid Arguments\n\n")
        print(help)
        exit()

    if sys.argv[1]=='raw_key':
        with open(sys.argv[2], 'r') as keyFile:
            for line in keyFile:
                key=line
                break
    elif sys.argv[1]=='short_key':
        paraphrase=sys.argv[2]
        sha256=hashlib.sha256(paraphrase.encode('utf-8')).hexdigest()
        key=' '.join(sha256[i:i+2] for i in range(0, len(sha256), 2))
    else:
        print("Invalid Arguments\n\n")
        print(help)
        exit()

    encrypt=True
    if sys.argv[3]=='encrypt':
        encrypt=True
    elif sys.argv[3]=='decrypt':
        encrypt=False
    else:
        print("Invalid Arguments\n\n")
        print(help)
        exit()

    ifile=sys.argv[4]
    ofile=sys.argv[5]

    slicedKey=sliceInitialKey(key)
    keyExpansion(slicedKey)
    for i in range(4):
        slicedKey.pop()

    ecb(ifile, ofile, slicedKey, encrypt)
    if encrypt:
        print("[+] Encryption Complete")
    else:
        print("[+] Decryption Complete")

_start()