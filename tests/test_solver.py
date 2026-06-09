from __future__ import annotations

import os
import base64
import bz2
import hashlib
import gzip
import lzma
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
import py_compile
import zlib
from pathlib import Path

from revbot.cli import discover_solve_targets
from revbot.models import ToolResult
from revbot.solver import SolveEngine, decode_string_variants, extract_flags, extract_pyc_strings, immediate_string_candidates, infer_inverse_transform, parse_hook_lines, parse_mem_hook_line, rc4_common_key_search, rc4_crypt, repeating_xor_search, score_runtime_output, xor_search


class SolverTests(unittest.TestCase):
    def test_extracts_literal_and_encoded_flags(self) -> None:
        self.assertIn("DH{abc_123}", extract_flags("xx DH{abc_123} yy"))
        decoded = decode_string_variants("REh7YmFzZTY0X2ZsYWd9")
        self.assertTrue(any("DH{base64_flag}" in value for value, _ in decoded))
        decoded32 = decode_string_variants("IREHWYTBONSTGMS7MZWGCZ35")
        self.assertTrue(any("DH{base32_flag}" in value for value, _ in decoded32))
        decoded58 = decode_string_variants("2uoRKznAz7QGLgbdSJCUU")
        self.assertTrue(any("DH{base58_flag}" in value for value, _ in decoded58))
        decoded_percent = decode_string_variants("%44%48%7B%75%72%6C%5F%66%6C%61%67%7D")
        self.assertTrue(any("DH{url_flag}" in value for value, _ in decoded_percent))
        decoded_urlsafe = decode_string_variants("REh7dXJsc2FmZV9mbGFnfQ")
        self.assertTrue(any("DH{urlsafe_flag}" in value for value, _ in decoded_urlsafe))
        decoded_escape = decode_string_variants(r"\x44\x48\x7b\x65\x73\x63\x5f\x66\x6c\x61\x67\x7d")
        self.assertTrue(any("DH{esc_flag}" in value for value, _ in decoded_escape))
        bit_string = "".join(f"{byte:08b}" for byte in b"DH{bits_flag}")
        decoded_bits = decode_string_variants(bit_string)
        self.assertTrue(any("DH{bits_flag}" in value for value, _ in decoded_bits))
        utf16_b64 = base64.b64encode("DH{utf16_flag}".encode("utf-16le")).decode()
        decoded_utf16 = decode_string_variants(utf16_b64)
        self.assertTrue(any("DH{utf16_flag}" in value for value, _ in decoded_utf16))
        utf16be_b64 = base64.b64encode("DH{utf16be_flag}".encode("utf-16be")).decode()
        decoded_utf16be = decode_string_variants(utf16be_b64)
        self.assertTrue(any("DH{utf16be_flag}" in value for value, _ in decoded_utf16be))
        utf32le_b64 = base64.b64encode("DH{utf32_flag}".encode("utf-32le")).decode()
        decoded_utf32le = decode_string_variants(utf32le_b64)
        self.assertTrue(any("DH{utf32_flag}" in value for value, _ in decoded_utf32le))
        decoded_qp = decode_string_variants("=44=48=7B=71=70=5F=66=6C=61=67=7D")
        self.assertTrue(any("DH{qp_flag}" in value for value, _ in decoded_qp))
        nested = base64.b64encode(b"44487b6e65737465645f666c61677d").decode()
        decoded_nested = decode_string_variants(nested)
        self.assertFalse(any("DH{nested_flag}" in value for value, _ in decoded_nested))
        decoded_morse = decode_string_variants("-.. .... -....- -- --- .-. ... .")
        self.assertTrue(any("DH-MORSE" in value for value, _ in decoded_morse))

    def test_xor_search_finds_single_byte_xor_flag(self) -> None:
        encoded = bytes(byte ^ 0x42 for byte in b"noise DH{xor_flag} tail")
        candidates = xor_search(encoded)
        self.assertTrue(any(candidate.value == "DH{xor_flag}" for candidate in candidates))

    def test_byte_shift_search_finds_shifted_blob_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shift.bin"
            path.write_bytes(bytes((byte + 9) & 0xFF for byte in b"noise DH{shift_blob} tail"))
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{shift_blob}")

    def test_bit_rotate_search_finds_rotated_blob_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rotate.bin"
            path.write_bytes(bytes(((byte << 3) | (byte >> 5)) & 0xFF for byte in b"noise DH{rotate_blob} tail"))
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{rotate_blob}")

    def test_repeating_xor_search_finds_common_key_flag(self) -> None:
        key = b"key"
        encoded = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(b"noise DH{rxor_flag} tail"))
        candidates = repeating_xor_search(encoded)
        self.assertTrue(any(candidate.value == "DH{rxor_flag}" for candidate in candidates))

    def test_repeating_xor_search_uses_embedded_key_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = b"s3cr3t"
            encoded = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(b"noise DH{embedded_key_xor} tail"))
            path = Path(tmp) / "rxor.bin"
            path.write_bytes(b"xor_key=s3cr3t\x00" + encoded)
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{embedded_key_xor}")

    def test_rc4_common_key_search(self) -> None:
        encoded = rc4_crypt(b"secret", b"DH{rc4_flag}")
        candidates = rc4_common_key_search(encoded)
        self.assertTrue(any(candidate.value == "DH{rc4_flag}" for candidate in candidates))

    def test_rc4_search_uses_embedded_key_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = b"purple7"
            path = Path(tmp) / "rc4.bin"
            path.write_bytes(b"rc4_key=purple7\x00" + rc4_crypt(key, b"DH{embedded_rc4_key}"))
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{embedded_rc4_key}")

    def test_parse_hook_lines(self) -> None:
        parsed = parse_hook_lines("REVHOOK|strcmp|test|open_sesame\n")
        self.assertEqual(parsed[0]["function"], "strcmp")
        self.assertEqual(parsed[0]["arg1"], "open_sesame")

    def test_parse_mem_hook_line(self) -> None:
        parsed = parse_mem_hook_line("REVHOOK_MEM|memcmp|4|74657374|6b657931")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["arg0"], "test")
        self.assertEqual(parsed["arg1"], "key1")

    def test_immediate_string_candidates_from_little_endian_mov(self) -> None:
        disasm = """
        0000000000001139 <main>:
            1139: 48 b8 6f 70 65 6e 5f 73 65 73    movabs rax,0x7365735f6e65706f
            1143: c7 45 f0 61 6d 65 00             mov    DWORD PTR [rbp-0x10],0x656d61
        """
        tools = {"objdump_disasm": ToolResult(name="objdump_disasm", available=True, stdout=disasm)}
        candidates = immediate_string_candidates(tools)
        self.assertTrue(any(candidate.value == "open_sesame" for candidate in candidates))

    def test_objdump_indexed_char_constraints(self) -> None:
        disasm = """
        0000000000001139 <check>:
            1139: 80 3f 44                    cmp    BYTE PTR [rdi],0x44
            113c: 80 7f 01 48                 cmp    BYTE PTR [rdi+0x1],0x48
            1140: 80 7f 02 7b                 cmp    BYTE PTR [rdi+0x2],0x7b
            1144: 80 7f 03 69                 cmp    BYTE PTR [rdi+0x3],0x69
            1148: 80 7f 04 64                 cmp    BYTE PTR [rdi+0x4],0x64
            114c: 80 7f 05 78                 cmp    BYTE PTR [rdi+0x5],0x78
            1150: 80 7f 06 7d                 cmp    BYTE PTR [rdi+0x6],0x7d
        """
        tools = {"objdump_disasm": ToolResult(name="objdump_disasm", available=True, stdout=disasm)}
        candidates = immediate_string_candidates(tools)
        self.assertTrue(any(candidate.value == "DH{idx}" for candidate in candidates))

    def test_objdump_movzx_then_register_cmp_constraints(self) -> None:
        disasm = """
        0000000000001139 <check>:
            1139: 0f b6 07                 movzx  eax,BYTE PTR [rdi]
            113c: 3c 44                    cmp    al,0x44
            113e: 0f b6 47 01              movzx  eax,BYTE PTR [rdi+0x1]
            1142: 3c 48                    cmp    al,0x48
            1144: 0f b6 47 02              movzx  eax,BYTE PTR [rdi+0x2]
            1148: 3c 7b                    cmp    al,0x7b
            114a: 0f b6 47 03              movzx  eax,BYTE PTR [rdi+0x3]
            114e: 3c 72                    cmp    al,0x72
            1150: 0f b6 47 04              movzx  eax,BYTE PTR [rdi+0x4]
            1154: 3c 65                    cmp    al,0x65
            1156: 0f b6 47 05              movzx  eax,BYTE PTR [rdi+0x5]
            115a: 3c 67                    cmp    al,0x67
            115c: 0f b6 47 06              movzx  eax,BYTE PTR [rdi+0x6]
            1160: 3c 7d                    cmp    al,0x7d
        """
        tools = {"objdump_disasm": ToolResult(name="objdump_disasm", available=True, stdout=disasm)}
        candidates = immediate_string_candidates(tools)
        self.assertTrue(any(candidate.value == "DH{reg}" for candidate in candidates))

    def test_korean_success_failure_output_scoring(self) -> None:
        self.assertGreaterEqual(score_runtime_output("\uc815\ub2f5\uc785\ub2c8\ub2e4"), 2)
        self.assertLess(score_runtime_output("\ud2c0\ub838\uc2b5\ub2c8\ub2e4"), 0)

    def test_infers_add_transform(self) -> None:
        inferred = infer_inverse_transform("test", "uftu", "pqfo`tftbnf")
        self.assertIn(("add_1", "open_sesame"), inferred)

    def test_solve_static_literal_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.bin"
            path.write_bytes(b"hello\x00DH{literal_flag}\x00")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{literal_flag}")

    def test_static_hint_value_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hint.bin"
            path.write_bytes(b"usage: password is hint_secret_42\x00")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "hint_secret_42")

    def test_caesar_and_atbash_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            caesar = Path(tmp) / "caesar.txt"
            atbash = Path(tmp) / "atbash.txt"
            rot47 = Path(tmp) / "rot47.txt"
            reverse_b64 = Path(tmp) / "reverse_b64.txt"
            caesar.write_text("GK{fdhvdu_iodj}", encoding="utf-8")
            atbash.write_text("WS{zgyzhs_uozt}", encoding="utf-8")
            rot47.write_text("swLC@Ecf07=28N", encoding="utf-8")
            reverse_b64.write_text("9RjNi9VZzJXZ2Vmc7hER", encoding="utf-8")
            caesar_result = SolveEngine(tool_timeout=2).solve(caesar)
            atbash_result = SolveEngine(tool_timeout=2).solve(atbash)
            rot47_result = SolveEngine(tool_timeout=2).solve(rot47)
            reverse_b64_result = SolveEngine(tool_timeout=2).solve(reverse_b64)
            self.assertEqual(caesar_result["candidates"][0]["value"], "DH{caesar_flag}")
            self.assertEqual(atbash_result["candidates"][0]["value"], "DH{atbash_flag}")
            self.assertEqual(rot47_result["candidates"][0]["value"], "DH{rot47_flag}")
            self.assertEqual(reverse_b64_result["candidates"][0]["value"], "DH{reverse_b64}")

    def test_solve_uses_extra_disassembler_artifact_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blank.bin"
            path.write_bytes(b"no direct flag here")
            artifact = {
                "path": "export.json",
                "loaded": True,
                "data": {
                    "source": "ghidra",
                    "strings": [{"value": "REh7YXJ0aWZhY3RfZmxhZ30="}],
                    "functions": [{"name": "check_password", "calls": [{"name": "strcmp"}], "strings": ["wrong password"]}],
                },
            }
            result = SolveEngine(tool_timeout=2).solve(path, extra_artifacts=[artifact])
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{artifact_flag}")
            self.assertEqual(result["ranked_functions"][0]["name"], "check_password")

    def test_solve_zip_embedded_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00DH{zip_flag}\x00")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{zip_flag}")

    def test_python_pyc_constants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "challenge.py"
            pyc = Path(tmp) / "challenge.pyc"
            py.write_text("secret = 'DH{pyc_flag}'\nprint('nope')\n", encoding="utf-8")
            py_compile.compile(str(py), cfile=str(pyc), doraise=True)
            strings = extract_pyc_strings(pyc.read_bytes())
            self.assertIn("DH{pyc_flag}", strings)
            result = SolveEngine(tool_timeout=2).solve(pyc)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{pyc_flag}")

    def test_python_pyc_numeric_constants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "numeric.py"
            pyc = Path(tmp) / "numeric.pyc"
            nums = tuple(b"DH{pyc_array}")
            py.write_text(f"nums = {nums!r}\nprint('nope')\n", encoding="utf-8")
            py_compile.compile(str(py), cfile=str(pyc), doraise=True)
            result = SolveEngine(tool_timeout=2).solve(pyc)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{pyc_array}")

    def test_script_artifact_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "challenge.js"
            js.write_text("const x = 'REh7anNfZmxhZ30=';\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{js_flag}")

    def test_brainfuck_output_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bf.txt"
            path.write_text(brainfuck_print_program("DH{bf_flag}"), encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{bf_flag}")

    def test_png_compressed_text_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hidden.png"
            payload = b"Comment\x00\x00" + zlib.compress(b"DH{png_ztxt_flag}")
            path.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + png_chunk(b"zTXt", payload)
                + png_chunk(b"IEND", b"")
            )
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{png_ztxt_flag}")

    def test_script_context_decoded_input_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "challenge.js"
            js.write_text(
                "const secret = atob('b3Blbl9zZXNhbWU=');\n"
                "if (input === secret) console.log('success');\n",
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "open_sesame")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for decoded input validation test")
    def test_decoded_non_flag_input_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "encoded.c"
            exe = Path(tmp) / "encoded"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    const char *encoded_hint = "b3Blbl9zZXNhbWU=";
                    int main(void) {
                      char buf[128] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "open_sesame") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "open_sesame")
            self.assertEqual(result["candidates"][0]["source"], "dynamic:validated-stdin")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for string variant probe test")
    def test_string_probe_variants_are_tried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "variant.c"
            exe = Path(tmp) / "variant"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    const char *hint = "open sesame";
                    int main(void) {
                      char buf[128] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "open_sesame") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "open_sesame")

    def test_execute_python_script_without_executable_bit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "runtime.py"
            py.write_text(
                textwrap.dedent(
                    r'''
                    import sys
                    value = sys.stdin.readline().strip()
                    if value == "py_runtime_secret":
                        print("success")
                    else:
                        print("fail")
                    '''
                ),
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(py)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "py_runtime_secret")

    def test_static_script_comparison_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "compare.py"
            py.write_text(
                "value = input().strip()\nif value == 'static_compare_secret': print('success')\n",
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2).solve(py)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "static_compare_secret")

    def test_python_ast_concatenated_comparison_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "ast_compare.py"
            py.write_text(
                "secret = 'ast_' + 'joined_' + 'secret'\nvalue = input().strip()\nif value == secret: print('success')\n",
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2).solve(py)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "ast_joined_secret")

    def test_python_ast_decoded_bytes_comparison_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "ast_decode.py"
            py.write_text(
                "secret = bytes.fromhex('70795f6465636f64655f736563726574').decode()\n"
                "value = input().strip()\nif value == secret: print('success')\n",
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2).solve(py)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "py_decode_secret")

    def test_static_c_source_comparison_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "compare.c"
            src.write_text(
                '#include <string.h>\nint ok(char *s) { return strcmp("source_secret", s) == 0; }\n',
                encoding="utf-8",
            )
            cpp = Path(tmp) / "compare.cpp"
            cpp.write_text('bool ok(std::string s) { return "left_literal_secret" == s; }\n', encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(src)
            cpp_result = SolveEngine(tool_timeout=2).solve(cpp)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "source_secret")
            self.assertEqual(cpp_result["candidates"][0]["value"], "left_literal_secret")

    def test_static_powershell_comparison_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "compare.ps1"
            src.write_text('if ($input -eq "ps_secret") { "success" }\n', encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(src)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "ps_secret")

    def test_static_contains_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "contains.js"
            py = Path(tmp) / "contains.py"
            java = Path(tmp) / "Equals.java"
            js.write_text("if (input.includes('contains_secret')) console.log('success');\n", encoding="utf-8")
            py.write_text("if 'python_contains_secret' in value: print('success')\n", encoding="utf-8")
            java.write_text('if (input.equals("java_equals_secret")) System.out.println("success");\n', encoding="utf-8")
            js_result = SolveEngine(tool_timeout=2).solve(js)
            py_result = SolveEngine(tool_timeout=2).solve(py)
            java_result = SolveEngine(tool_timeout=2).solve(java)
            self.assertEqual(js_result["candidates"][0]["value"], "contains_secret")
            self.assertEqual(py_result["candidates"][0]["value"], "python_contains_secret")
            self.assertEqual(java_result["candidates"][0]["value"], "java_equals_secret")

    def test_charcode_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "charcode.js"
            js.write_text("const flag = String.fromCharCode(68,72,123,99,104,97,114,99,111,100,101,125);\n", encoding="utf-8")
            py = Path(tmp) / "chr.py"
            py.write_text("flag = chr(68)+chr(72)+chr(123)+chr(99)+chr(104)+chr(114)+chr(125)\n", encoding="utf-8")
            js_result = SolveEngine(tool_timeout=2).solve(js)
            py_result = SolveEngine(tool_timeout=2).solve(py)
            self.assertEqual(js_result["candidates"][0]["value"], "DH{charcode}")
            self.assertEqual(py_result["candidates"][0]["value"], "DH{chr}")

    def test_source_char_literal_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "literal_chars.c"
            src.write_text(
                "char secret[] = {'D','H','{','c','h','a','r','s','}'};\n",
                encoding="utf-8",
            )
            result = SolveEngine(tool_timeout=2).solve(src)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{chars}")

    def test_source_char_constraints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            c_src = Path(tmp) / "chars.c"
            c_src.write_text(
                "int ok(char *s) { return s[0]=='D' && s[1]=='H' && s[2]=='{' && s[3]=='c' && s[4]=='h' && s[5]=='}'; }\n",
                encoding="utf-8",
            )
            py_src = Path(tmp) / "xor_chars.py"
            encoded = [ord(ch) ^ 3 for ch in "DH{xor}"]
            checks = " and ".join(f"(ord(s[{idx}]) ^ 3) == {value}" for idx, value in enumerate(encoded))
            py_src.write_text(f"if {checks}: print('success')\n", encoding="utf-8")
            c_result = SolveEngine(tool_timeout=2).solve(c_src)
            py_result = SolveEngine(tool_timeout=2).solve(py_src)
            self.assertEqual(c_result["candidates"][0]["value"], "DH{ch}")
            self.assertEqual(py_result["candidates"][0]["value"], "DH{xor}")

    def test_js_char_at_constraints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "charat.js"
            checks = " && ".join(
                f"s.charCodeAt({idx}) === {ord(ch)}" for idx, ch in enumerate("DH{js}")
            )
            js.write_text(f"if ({checks}) console.log('success');\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertEqual(result["candidates"][0]["value"], "DH{js}")

    def test_js_char_code_transformed_constraints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "charxor.js"
            checks = " && ".join(
                f"s.charCodeAt({idx}) ^ 7 === {ord(ch) ^ 7}" for idx, ch in enumerate("DH{jsxor}")
            )
            js.write_text(f"if ({checks}) console.log('success');\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertEqual(result["candidates"][0]["value"], "DH{jsxor}")

    def test_script_numeric_array_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "array.js"
            values = ",".join(str(byte) for byte in b"DH{array_flag}")
            js.write_text(f"const flag = [{values}].map(x => String.fromCharCode(x)).join('');\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{array_flag}")

    def test_transformed_numeric_array_probe_input_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "array_input.py"
            encoded = ",".join(str(byte ^ 7) for byte in b"array_secret")
            py.write_text(
                f"enc = [{encoded}]\n"
                "secret = ''.join(chr(x ^ 7) for x in enc)\n"
                "value = input().strip()\n"
                "print('success' if value == secret else 'fail')\n",
                encoding="utf-8",
            )
            result = SolveEngine(
                tool_timeout=2,
                execute=True,
                exec_timeout=1.0,
                max_probes=1000,
                validation_limit=1000,
            ).solve(py)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "array_secret")

    def test_shifted_numeric_array_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            js = Path(tmp) / "shifted.js"
            values = ",".join(str((byte + 7) & 0xFF) for byte in b"DH{shift_array}")
            js.write_text(f"const enc = [{values}];\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(js)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{shift_array}")

    def test_whitespace_numeric_sequence_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "numbers.txt"
            path.write_text("payload: " + " ".join(str(byte) for byte in b"DH{space_nums}"), encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{space_nums}")

    def test_hash_crack_embedded_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hash.txt"
            digest = hashlib.sha256(b"dreamhack").hexdigest()
            path.write_text(f"target_sha256={digest}\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "dreamhack")

    def test_hash_crack_embedded_salted_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "salted.txt"
            digest = hashlib.sha1(b"SALT42" + b"dreamhack").hexdigest()
            path.write_text(f"salt=SALT42\nsha1={digest}\n", encoding="utf-8")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "dreamhack")

    def test_compressed_stream_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gz_path = Path(tmp) / "gzip.bin"
            zlib_path = Path(tmp) / "zlib.bin"
            bz2_path = Path(tmp) / "bzip2.bin"
            xz_path = Path(tmp) / "xz.bin"
            gz_path.write_bytes(b"prefix" + gzip.compress(b"DH{gzip_flag}") + b"tail")
            zlib_path.write_bytes(b"prefix" + zlib.compress(b"DH{zlib_flag}") + b"tail")
            bz2_path.write_bytes(bz2.compress(b"DH{bzip2_flag}"))
            xz_path.write_bytes(lzma.compress(b"DH{xz_flag}"))
            gz_result = SolveEngine(tool_timeout=2).solve(gz_path)
            zlib_result = SolveEngine(tool_timeout=2).solve(zlib_path)
            bz2_result = SolveEngine(tool_timeout=2).solve(bz2_path)
            xz_result = SolveEngine(tool_timeout=2).solve(xz_path)
            self.assertEqual(gz_result["candidates"][0]["value"], "DH{gzip_flag}")
            self.assertEqual(zlib_result["candidates"][0]["value"], "DH{zlib_flag}")
            self.assertEqual(bz2_result["candidates"][0]["value"], "DH{bzip2_flag}")
            self.assertEqual(xz_result["candidates"][0]["value"], "DH{xz_flag}")

    def test_nested_decoding_in_solve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nested_path = Path(tmp) / "nested.txt"
            compressed_path = Path(tmp) / "compressed.txt"
            nested_path.write_text(base64.b64encode(b"44487b6e65737465645f666c61677d").decode(), encoding="utf-8")
            compressed_path.write_text(base64.b64encode(zlib.compress(b"DH{b64_zlib_flag}")).decode(), encoding="utf-8")
            nested_result = SolveEngine(tool_timeout=2).solve(nested_path)
            compressed_result = SolveEngine(tool_timeout=2).solve(compressed_path)
            self.assertEqual(nested_result["candidates"][0]["value"], "DH{nested_flag}")
            self.assertEqual(compressed_result["candidates"][0]["value"], "DH{b64_zlib_flag}")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for no-input output solve test")
    def test_dynamic_no_input_output_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "printflag.c"
            exe = Path(tmp) / "printflag"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    int main(void) {
                      puts("DH{printed_without_input}");
                      return 0;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "DH{printed_without_input}")

    def test_zip_class_embedded_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Demo.class", b"\xca\xfe\xba\xbe\x00DH{jar_flag}\x00")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{jar_flag}")

    def test_tar_archive_embedded_flag_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flag_file = root / "flag.txt"
            source_file = root / "check.js"
            tar_path = root / "bundle.tgz"
            flag_file.write_text("DH{tar_flag}", encoding="utf-8")
            source_file.write_text("if (input === 'tar_source_secret') console.log('success');\n", encoding="utf-8")
            with tarfile.open(tar_path, "w:gz") as archive:
                archive.add(flag_file, arcname="flag.txt")
                archive.add(source_file, arcname="check.js")
            result = SolveEngine(tool_timeout=2).solve(tar_path)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("DH{tar_flag}", values)
            self.assertIn("tar_source_secret", values)

    def test_zip_entry_source_comparison_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("check.js", "if (input === 'zip_source_secret') console.log('success');\n")
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "zip_source_secret")

    def test_zip_archive_comment_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "comment.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("readme.txt", "nothing")
                archive.comment = b"DH{zip_comment_flag}"
            result = SolveEngine(tool_timeout=2).solve(path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{zip_comment_flag}")

    def test_appended_zip_payload_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "payload.zip"
            sample_path = Path(tmp) / "self_extracting.bin"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("flag.txt", "DH{appended_zip}")
            sample_path.write_bytes(b"MZfake-loader" + archive_path.read_bytes())
            result = SolveEngine(tool_timeout=2).solve(sample_path)
            self.assertTrue(result["solved"])
            self.assertEqual(result["candidates"][0]["value"], "DH{appended_zip}")

    def test_discover_solve_targets_includes_scripts_and_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ["a.js", "b.py", "c.pyc", "d.apk", "ignore.c", "ignore.txt"]:
                (root / name).write_bytes(b"x")
            names = [path.name for path in discover_solve_targets(root)]
            self.assertIn("a.js", names)
            self.assertIn("b.py", names)
            self.assertIn("c.pyc", names)
            self.assertIn("d.apk", names)
            self.assertNotIn("ignore.c", names)
            self.assertNotIn("ignore.txt", names)
            source_names = [path.name for path in discover_solve_targets(root, include_source=True)]
            text_names = [path.name for path in discover_solve_targets(root, include_text=True)]
            self.assertIn("ignore.c", source_names)
            self.assertIn("ignore.txt", text_names)

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for dynamic solve test")
    def test_dynamic_probe_finds_password_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "crackme.c"
            exe = Path(tmp) / "crackme"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char buf[128] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "open_sesame") == 0) {
                        puts("correct");
                        return 0;
                      }
                      puts("wrong");
                      return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            os.chmod(exe, 0o755)
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("open_sesame", values)
            self.assertEqual(result["candidates"][0]["source"], "dynamic:validated-stdin")
            self.assertTrue(result["dynamic"]["candidate_validation"][0]["success_score"] >= 2)

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for custom candidate test")
    def test_custom_candidate_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "custom.c"
            exe = Path(tmp) / "custom"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(int argc, char **argv) {
                      char buf[128] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "from_wordlist") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            os.chmod(exe, 0o755)
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["from_wordlist"]).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "from_wordlist")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for raw stdin solve test")
    def test_raw_stdin_probe_without_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "raw.c"
            exe = Path(tmp) / "raw"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    #include <unistd.h>
                    int main(void) {
                      char buf[32] = {0};
                      int n = read(0, buf, sizeof(buf));
                      if (n == 10 && memcmp(buf, "raw_secret", 10) == 0) {
                        puts("success");
                        return 0;
                      }
                      puts("fail");
                      return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["raw_secret"]).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "raw_secret")
            self.assertEqual(result["candidates"][0]["source"], "dynamic:validated-stdin-raw")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for multi-stdin solve test")
    def test_multi_stdin_probe_for_login_then_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "login.c"
            exe = Path(tmp) / "login"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char user[64] = {0};
                      char pass[64] = {0};
                      if (!fgets(user, sizeof(user), stdin)) return 1;
                      if (!fgets(pass, sizeof(pass), stdin)) return 1;
                      user[strcspn(user, "\n")] = 0;
                      pass[strcspn(pass, "\n")] = 0;
                      if (strcmp(user, "admin") == 0 && strcmp(pass, "multi_secret") == 0) {
                        puts("success");
                        return 0;
                      }
                      puts("fail");
                      return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "multi_secret")
            self.assertEqual(result["candidates"][0]["source"], "dynamic:validated-stdin-admin-candidate")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for env/file solve test")
    def test_env_and_file_input_probes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_src = tmp_path / "envme.c"
            env_exe = tmp_path / "envme"
            env_src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <stdlib.h>
                    #include <string.h>
                    int main(void) {
                      char *key = getenv("KEY");
                      if (key && strcmp(key, "env_secret") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            file_src = tmp_path / "fileme.c"
            file_exe = tmp_path / "fileme"
            file_src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char buf[128] = {0};
                      FILE *f = fopen("input.txt", "r");
                      if (!f) return 1;
                      fgets(buf, sizeof(buf), f);
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "file_secret") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(env_src), "-o", str(env_exe)])
            subprocess.check_call(["gcc", str(file_src), "-o", str(file_exe)])
            env_result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["env_secret"]).solve(env_exe)
            file_result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["file_secret"]).solve(file_exe)
            self.assertEqual(env_result["candidates"][0]["source"], "dynamic:validated-env")
            self.assertEqual(file_result["candidates"][0]["source"], "dynamic:validated-file")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for env/file hint solve test")
    def test_dynamic_hook_discovers_custom_env_and_file_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_src = tmp_path / "envhint.c"
            env_exe = tmp_path / "envhint"
            env_src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <stdlib.h>
                    #include <string.h>
                    int main(void) {
                      char *key = getenv("SPECIAL_CODE");
                      if (key && strcmp(key, "env_hint_secret") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            file_src = tmp_path / "filehint.c"
            file_exe = tmp_path / "filehint"
            file_src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char buf[128] = {0};
                      FILE *f = fopen("data/secret.in", "r");
                      if (!f) return 1;
                      fgets(buf, sizeof(buf), f);
                      buf[strcspn(buf, "\n")] = 0;
                      if (strcmp(buf, "file_hint_secret") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(env_src), "-o", str(env_exe)])
            subprocess.check_call(["gcc", str(file_src), "-o", str(file_exe)])
            env_result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(env_exe)
            file_result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(file_exe)
            self.assertIn("SPECIAL_CODE", env_result["dynamic"]["input_hints"]["env_names"])
            self.assertEqual(env_result["candidates"][0]["value"], "env_hint_secret")
            self.assertIn("data/secret.in", file_result["dynamic"]["input_hints"]["file_names"])
            self.assertEqual(file_result["candidates"][0]["value"], "file_hint_secret")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for PIN bruteforce solve test")
    def test_dynamic_pin_bruteforce(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "pin.c"
            exe = Path(tmp) / "pin"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    #include <stdlib.h>
                    int main(void) {
                      char buf[16] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      if (strlen(buf) == 4 && buf[0] == '0' && buf[1] == '0' && atoi(buf) == 42) {
                        puts("success");
                        return 0;
                      }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(
                tool_timeout=2,
                execute=True,
                exec_timeout=1.0,
                bruteforce_pin=True,
                max_probes=64,
            ).solve(exe)
            self.assertEqual(result["candidates"][0]["value"], "0042")

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for argv solve test")
    def test_argv_probe_finds_password_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "argvme.c"
            exe = Path(tmp) / "argvme"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(int argc, char **argv) {
                      if (argc < 2) return 1;
                      if (strcmp(argv[1], "argv_secret") == 0) {
                        puts("success");
                        return 0;
                      }
                      puts("fail");
                      return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            os.chmod(exe, 0o755)
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0).solve(exe)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("argv_secret", values)

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for immediate solve test")
    def test_static_immediate_candidate_from_char_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "chars.c"
            exe = Path(tmp) / "chars"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    int main(int argc, char **argv) {
                      if (argc < 2) return 1;
                      if (argv[1][0] == 'p' && argv[1][1] == 'i' && argv[1][2] == 'n' &&
                          argv[1][3] == '4' && argv[1][4] == '2' && argv[1][5] == 0) {
                        puts("success");
                        return 0;
                      }
                      puts("fail");
                      return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", "-O0", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=False, exec_timeout=1.0).solve(exe)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("pin42", values)

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for transform solve test")
    def test_transform_inference_from_hook_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "transform.c"
            exe = Path(tmp) / "transform"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char buf[128] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      for (int i = 0; buf[i]; i++) buf[i] = buf[i] + 1;
                      if (strcmp(buf, "pqfo`tftbnf") == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            os.chmod(exe, 0o755)
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["test"]).solve(exe)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("open_sesame", values)

    @unittest.skipIf(not shutil.which("gcc"), "gcc is required for memcmp solve test")
    def test_memcmp_hook_extracts_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "mem.c"
            exe = Path(tmp) / "mem"
            src.write_text(
                textwrap.dedent(
                    r'''
                    #include <stdio.h>
                    #include <string.h>
                    int main(void) {
                      char buf[32] = {0};
                      if (!fgets(buf, sizeof(buf), stdin)) return 1;
                      buf[strcspn(buf, "\n")] = 0;
                      const char secret[] = {'m','e','m','k','e','y',0};
                      if (memcmp(buf, secret, 6) == 0) { puts("success"); return 0; }
                      puts("fail"); return 1;
                    }
                    '''
                ),
                encoding="utf-8",
            )
            subprocess.check_call(["gcc", str(src), "-o", str(exe)])
            result = SolveEngine(tool_timeout=2, execute=True, exec_timeout=1.0, custom_inputs=["testxx"]).solve(exe)
            values = [item["value"] for item in result["candidates"]]
            self.assertIn("memkey", values)

def brainfuck_print_program(text: str) -> str:
    current = 0
    parts = []
    for ch in text.encode("latin1"):
        up = (ch - current) % 256
        down = (current - ch) % 256
        if up <= down:
            parts.append("+" * up)
        else:
            parts.append("-" * down)
        parts.append(".")
        current = ch
    return "".join(parts)


def png_chunk(name: bytes, payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + name + payload + b"\x00\x00\x00\x00"


if __name__ == "__main__":
    unittest.main()
