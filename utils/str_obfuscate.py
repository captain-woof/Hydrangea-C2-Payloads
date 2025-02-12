import sys
import random

# Generated with keygen.py
encKey = b"\x28\x4B\x1C\x70\xE6\xDE\x83\x09\x2C\x51\x22\xC5\x5A\xE4\x62\xC2\x4D\x6D\x81\x7E\x56\x8C\xE3\xF4\xAE\x70\xDD\x47\x6F\x0D\x5B\x21"
encKeyLen = len(encKey)

def shuffleString(strIn: str):
    strInLen = len(strIn)
    strOut = ""

    i = 0
    j = strInLen - 1

    while i < j:
        strOut += strIn[i]
        strOut += strIn[j]

        i += 1
        j -= 1

    if strInLen % 2 != 0:
        strOut += strIn[i]

    return strOut

def xorEncrypt(strIn: str):
    strOut = b""

    for index, character in enumerate(strIn):
        strOut += (ord(character) ^ encKey[index % encKeyLen]).to_bytes()

    return strOut

def obfuscateString(strIn: str):
    strInLen = len(strIn)

    strShuffled = shuffleString(strIn)
    strXord = xorEncrypt(strShuffled)
    strDeentropied = strXord + (b"a" * strInLen)

    return strDeentropied

def printBytes(bytesToPrint: bytes):
    for b in bytesToPrint:
        print(f"\\x{b:02x}", end="")

def printObfuscatedStr(strToObfuscate: str):
    strObfuscated = obfuscateString(strToObfuscate)

    print(f"CHAR strObfuscated[] = \"", end="")
    printBytes(strObfuscated)
    print("\";")

    print(f"DWORD strLen = {len(strToObfuscate)};")
    print(f"DWORD strObfuscatedLen = {len(strObfuscated)};")

if __name__ == "__main__":
    # Print encryption key
    print("CHAR encKey = \"", end="")
    printBytes(encKey)
    print("\";")
    print(f"int encKeyLen = {encKeyLen};")    

    # Print obfuscated string

    ## Shell mode
    if len(sys.argv) < 2:
        while True:
            try:
                strToObfuscate = input("Enter string to obfuscate: ").rstrip("\n")
                printObfuscatedStr(strToObfuscate)
            except KeyboardInterrupt:
                break
        pass
    
    ## One-shot mode
    else:
        printObfuscatedStr(sys.argv[1])