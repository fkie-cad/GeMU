from pathlib import Path
from random import randbytes, seed
import yara
import subprocess


program_template = """
// Check windows
#if _WIN32 || _WIN64
   #if _WIN64
     #define ENV64BIT
  #else
    #define ENV32BIT
  #endif
#endif

// Check GCC
#if __GNUC__
  #if __x86_64__ || __ppc64__
    #define ENV64BIT
  #else
    #define ENV32BIT
  #endif
#endif

#if defined(ENV64BIT)
unsigned char encrypted_shellcode[] = "{}";
#elif defined (ENV32BIT)
unsigned char encrypted_shellcode[] = "{}";
#else
    #error "Must define either ENV32BIT or ENV64BIT"
#endif

unsigned char key[] = "{}";

unsigned char get_shellcode_byte(int offset){{
    return encrypted_shellcode[offset] ^ key[offset];
}}
"""

TEST_FOLDER = Path(__file__).parent

#requires nasm
def assemble_shellcode() -> str:
    asm_file = TEST_FOLDER/"shellcode32.asm"
    output_path = TEST_FOLDER/"shellcode32"
    command = f"nasm -o {output_path} {asm_file}"
    result = subprocess.run(command, shell=True, cwd=str(TEST_FOLDER))
    assert result.returncode == 0
    return str(output_path)

def encrypt_shellcode(shellcode: bytes, key: bytes) -> bytes:
    return bytes([b ^ k for (b,k) in zip(shellcode, key)])

def generate_yara_rule(shellcode32, shellcode64):
    rule_str = f"rule shellcode32 {{strings: $hex = {{ {shellcode32.hex(" ")} }} condition: $hex }}"
    rule_str += f"rule shellcode64 {{strings: $hex = {{ {shellcode64.hex(" ")} }} condition: $hex }}"
    rule = yara.compile(source=rule_str)
    rule.save(str(TEST_FOLDER/"shellcode.yarc"))

def generate_shellcode_c_file(shellcode32: bytes, shellcode64: bytes):
    key = randbytes(max(len(shellcode32), len(shellcode64)))
    shellcode32 = encrypt_shellcode(shellcode32, key)
    shellcode64 = encrypt_shellcode(shellcode64, key)

    formated_shellcode32 = "\\x" + shellcode32.hex(" ").replace(" ", "\\x")
    formated_shellcode64 = "\\x" + shellcode64.hex(" ").replace(" ", "\\x")
    formated_key = "\\x" + key.hex(" ").replace(" ", "\\x")
    source = program_template.format(formated_shellcode64, formated_shellcode32, formated_key)

    c_file = TEST_FOLDER/"encrypted_shellcode.c"
    c_file.write_text(source)

def get_shellcode(bitness: int) -> bytes:
    # # shellcode = "\x31\xc0\x50\x68\x65\x73\x73\x61\x68\x4d\x65\x73\x73\x89\xe1\x50\x68\x6f\x78\x41\x41\x68\x4d\x65\x73\x73\x68\x41\x41\x41\x41\x89\xe1\x50\x51\x53\xb8\xea\x07\x45\x7e\xff\xd0";
    # shellcode_file = assemble_shellcode()
    shellcode_file = Path(__file__).parent / f"ShellcodeTemplate.x{86 if bitness==32 else 64}.bin"
    shellcode = shellcode_file.read_bytes()
    seed(0xdeadbeef)
    shellcode += b"testgemu"+randbytes(128)
    return shellcode

def generate_shellcode_main():
    shellcode32 = get_shellcode(32)
    shellcode64 = get_shellcode(64)
    generate_shellcode_c_file(shellcode32, shellcode64)
    generate_yara_rule(shellcode32, shellcode64)


if __name__ == "__main__":
    generate_shellcode_main()
