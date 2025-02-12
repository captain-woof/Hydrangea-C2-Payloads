import random

if __name__ == "__main__":
    
    
    keyLen = 32
    encKey = random.randbytes(keyLen)

    # For C/C++
    print("/* For C/C++ */")
    print("CHAR encKey = \"", end="")

    for b in encKey:
        print(f"\\x{b:02X}", end="")

    print("\";")
    print(f"int encKeyLen = {keyLen};")

    # For Python3
    print("# For Python3")
    print("encKey = b\"", end="")
    for b in encKey:
        print(f"\\x{b:02X}", end="")
    print("\"")