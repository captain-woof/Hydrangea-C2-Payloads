import sys
import re

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

def pascalToSnakeCapitalised(strToConvert):
    if not strToConvert:
        return ""
    snake_case = re.sub(r'([A-Z])', r'_\1', strToConvert)
    # Remove leading underscore if the string started with uppercase (e.g., "IsATree" becomes "_Is_A_Tree", then "IS_A_TREE")
    if snake_case.startswith('_'):
        snake_case = snake_case[1:]
    return snake_case.upper()

def printObfuscatedStr(strToObfuscate: str):
    strObfuscated = obfuscateString(strToObfuscate)
    strVariableName = pascalToSnakeCapitalised(strToObfuscate)

    print(f"CHAR STRING_{strVariableName}[] = \"", end="")
    printBytes(strObfuscated)
    print(f"\"; // \"{strToObfuscate}\"")

    print(f"DWORD STRING_{strVariableName}_LEN = {len(strToObfuscate)};")
    print(f"DWORD STRING_{strVariableName}_OBFUSCATED_LEN = {len(strObfuscated)};")

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
        # If it's a file, use it as input
        try:
            with open(sys.argv[1], "r") as fileInput:
                for strToObfuscate in fileInput:
                    printObfuscatedStr(strToObfuscate.rstrip("\n"))
            exit(0)
        except Exception:
            pass

        printObfuscatedStr(sys.argv[1])