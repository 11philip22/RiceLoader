import argparse

from ShellcodeRDI import *
from ShellcodeToUUID import convert_to_uuid
from typing import Iterable, Any, Tuple
from crypter import encrypt, xor_payload


__version__ = '1.0'


def signal_last(it: Iterable[Any]) -> Iterable[Tuple[bool, Any]]:
    iterable = iter(it)
    ret_var = next(iterable)
    for value in iterable:
        yield False, ret_var
        ret_var = value
    yield True, ret_var


def main():
    parser = argparse.ArgumentParser(description='RDI Shellcode Converter', conflict_handler='resolve')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
    parser.add_argument('input_dll', help='DLL to convert to shellcode')
    parser.add_argument('-f', '--function-name', dest='function_name',
                        help='The function to call after DllMain', default='SayHello')
    parser.add_argument('-u', '--user-data', dest='user_data',
                        help='Data to pass to the target function', default='dave')
    parser.add_argument('-c', '--clear-header', dest='clear_header', action='store_true',
                        help='Clear the PE header on load')
    parser.add_argument('-i', '--obfuscate-imports', dest='obfuscate_imports', action='store_true',
                        help='Randomize import dependency load order', default=False)
    parser.add_argument('-d', '--import-delay', dest='import_delay',
                        help='Number of seconds to pause between loading imports', type=int, default=0)
    parser.add_argument('-fb', '--bin-file', dest='bin_file', type=str,
                        help='Write the Dll shellcode to file')
    parser.add_argument('-fh', '--header-file', dest='header_file', type=str,
                        help='Write the UUIDS to a C header')
    parser.add_argument('-eh', '--encrypt-uuids', dest='crypt_header_file', type=str,
                        help='Encrypt uuids and write to C header')
    arguments = parser.parse_args()

    flags = 0

    if arguments.clear_header:
        flags |= 0x1

    if arguments.obfuscate_imports:
        flags = flags | 0x4 | arguments.import_delay << 16

    with open(arguments.input_dll, 'rb') as dll:
        converted_dll = ConvertToShellcode(
            dll.read(),
            HashFunctionName(arguments.function_name),
            arguments.user_data.encode(),
            flags
        )
    if arguments.crypt_header_file:
        converted_dll = xor_payload(converted_dll)

    if arguments.bin_file:
        print('[+] Creating Shellcode: {}'.format(arguments.bin_file))
        with open(arguments.bin_file, 'wb') as f:
            f.write(converted_dll)

    uuids = convert_to_uuid(converted_dll)
    print(*uuids, sep=',\n')

    if arguments.crypt_header_file:
        print('\n[+] Creating encrypted UUID header: {}'.format(arguments.crypt_header_file))
        key_str, iv_str, encrypted_uuids_str = encrypt(uuids)
        print(*encrypted_uuids_str, sep=',\n')

        with open(arguments.crypt_header_file, 'wb') as f:
            f.writelines([
                b'#pragma once\n',
                b'/* Header generated by: PE2SH2UUID */\n\n',
                bytes(f'unsigned char key[32] = {key_str};\n', encoding='utf-8'),
                bytes(f'unsigned char iv[16] = {iv_str};\n\n', encoding='utf-8'),
                bytes(f'unsigned char encryptedUuids[{len(encrypted_uuids_str)}][48] = \n', encoding='utf-8'),
                b'{\n'
            ])
            for is_last_element, uuid in signal_last(encrypted_uuids_str):
                if is_last_element:
                    line = f'    {uuid}\n'
                else:
                    line = f'    {uuid},\n'
                f.write(bytes(line, encoding='utf-8'))
            f.write(b'};')

    if arguments.header_file:
        print('\n[+] Creating UUID header: {}'.format(arguments.header_file))
        with open(arguments.header_file, 'wb') as f:
            f.writelines([
                b'#pragma once\n',
                b'/* Header generated by: PE2SH2UUID */\n\n'
                b'const char* uuids[] =\n',
                b'{\n'
            ])
            for is_last_element, uuid in signal_last(uuids):
                if is_last_element:
                    line = f'    {uuid}\n'
                else:
                    line = f'    {uuid},\n'
                f.write(bytes(line, encoding='utf-8'))
            f.write(b'};')


if __name__ == '__main__':
    main()
