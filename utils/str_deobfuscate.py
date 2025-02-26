import sys
import re

def pascalToSnakeCapitalised(strToConvert):
    if not strToConvert:
        return ""
    snake_case = re.sub(r'([A-Z])', r'_\1', strToConvert)
    # Remove leading underscore if the string started with uppercase (e.g., "IsATree" becomes "_Is_A_Tree", then "IS_A_TREE")
    if snake_case.startswith('_'):
        snake_case = snake_case[1:]
    return snake_case.upper()

def printDeobfuscationRoutine(strToDeobfuscate):
    strToDeobfuscateCap = pascalToSnakeCapitalised(strToDeobfuscate)

    print(f"""static CHAR str{strToDeobfuscate}[STRING_{strToDeobfuscateCap}_LEN + 1] = ""; // "{strToDeobfuscate}"
DeobfuscateUtf8String(
	(PCHAR)STRING_{strToDeobfuscateCap},
	STRING_{strToDeobfuscateCap}_LEN,
	str{strToDeobfuscate});""")

if __name__ == "__main__":
    # Print deobfuscated string routine

    ## Shell mode
    if len(sys.argv) < 2:
        while True:
            try:
                strToDeobfuscate = input("Enter string to deobfuscate: ").rstrip("\n")
                printDeobfuscationRoutine(strToDeobfuscate)
            except KeyboardInterrupt:
                break
        pass
    
    ## One-shot mode
    else:
        # If it's a file, use it as input
        try:
            with open(sys.argv[1], "r") as fileInput:
                for strToDeobfuscate in fileInput:
                    printDeobfuscationRoutine(strToDeobfuscate.rstrip("\n"))
            exit(0)
        except Exception:
            pass

        printDeobfuscationRoutine(sys.argv[1])