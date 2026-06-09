# Ghidra Python/Jython script. Run from Script Manager or headless analyzer.

import json
import os

from ghidra.program.model.symbol import RefType


def get_strings(limit=20000):
    values = []
    listing = currentProgram.getListing()
    for item in listing.getDefinedData(True):
        if len(values) >= limit:
            break
        value = item.getValue()
        if value is None:
            continue
        text = str(value)
        if len(text) >= 4:
            values.append({"address": str(item.getAddress()), "value": text})
    return values


def get_functions(limit=20000):
    listing = currentProgram.getListing()
    functions = []
    for function in currentProgram.getFunctionManager().getFunctions(True):
        if len(functions) >= limit:
            break
        calls = []
        strings = []
        body = function.getBody()
        instructions = listing.getInstructions(body, True)
        for instruction in instructions:
            for ref in instruction.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    target_function = getFunctionAt(target)
                    calls.append(
                        {
                            "address": str(instruction.getAddress()),
                            "target": str(target),
                            "name": target_function.getName() if target_function else "",
                        }
                    )
                if ref.getReferenceType() == RefType.DATA:
                    data = listing.getDataAt(ref.getToAddress())
                    if data and data.getValue() is not None:
                        text = str(data.getValue())
                        if len(text) >= 4:
                            strings.append({"address": str(ref.getToAddress()), "value": text})
        functions.append(
            {
                "entry": str(function.getEntryPoint()),
                "name": function.getName(),
                "body": str(body),
                "calls": calls[:200],
                "strings": strings[:200],
            }
        )
    return functions


def get_imports():
    imports = []
    symbol_table = currentProgram.getSymbolTable()
    for symbol in symbol_table.getExternalSymbols():
        imports.append(
            {
                "name": symbol.getName(),
                "library": symbol.getParentNamespace().getName(),
                "address": str(symbol.getAddress()),
            }
        )
    return imports


def main():
    program_path = currentProgram.getExecutablePath()
    if not program_path:
        program_path = currentProgram.getName()
    output_path = os.path.abspath(currentProgram.getName() + ".revbot.ghidra.json")
    data = {
        "source": "ghidra",
        "program": currentProgram.getName(),
        "executable_path": program_path,
        "image_base": str(currentProgram.getImageBase()),
        "imports": get_imports(),
        "strings": get_strings(),
        "functions": get_functions(),
    }
    with open(output_path, "w") as handle:
        json.dump(data, handle, indent=2)
    print("revbot export written to %s" % output_path)


main()

