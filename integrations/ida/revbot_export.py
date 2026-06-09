import json
import os

import idaapi
import idautils
import idc


def get_strings(limit=20000):
    values = []
    for item in idautils.Strings():
        values.append({"ea": int(item.ea), "value": str(item)})
        if len(values) >= limit:
            break
    return values


def get_functions(limit=20000):
    functions = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        end = idc.find_func_end(ea)
        calls = []
        strings = []
        for head in idautils.FuncItems(ea):
            if idc.print_insn_mnem(head).lower().startswith("call"):
                target = idc.get_operand_value(head, 0)
                calls.append({"ea": int(head), "target": int(target), "name": idc.get_name(target)})
            for ref in idautils.DataRefsFrom(head):
                value = idc.get_strlit_contents(ref)
                if value:
                    try:
                        decoded = value.decode("utf-8", "replace")
                    except AttributeError:
                        decoded = str(value)
                    strings.append({"ea": int(ref), "value": decoded})
        functions.append(
            {
                "ea": int(ea),
                "end": int(end),
                "name": name,
                "size": int(max(0, end - ea)),
                "calls": calls[:200],
                "strings": strings[:200],
            }
        )
        if len(functions) >= limit:
            break
    return functions


def get_imports():
    imports = []
    for index in range(idaapi.get_import_module_qty()):
        module_name = idaapi.get_import_module_name(index) or "unknown"

        def visitor(ea, name, ordinal):
            imports.append({"dll": module_name, "name": name or ("ordinal_%s" % ordinal), "ea": int(ea)})
            return True

        idaapi.enum_import_names(index, visitor)
    return imports


def main():
    input_path = idaapi.get_input_file_path()
    output_path = os.path.splitext(input_path)[0] + ".revbot.ida.json"
    data = {
        "source": "ida",
        "input_path": input_path,
        "image_base": int(idaapi.get_imagebase()),
        "imports": get_imports(),
        "strings": get_strings(),
        "functions": get_functions(),
    }
    with open(output_path, "w") as handle:
        json.dump(data, handle, indent=2)
    print("revbot export written to %s" % output_path)


if __name__ == "__main__":
    main()

