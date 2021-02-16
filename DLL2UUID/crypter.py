from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def generate_byte_file_string(byte_arr):
    return '{' + ",".join('0x{:02x}'.format(x) for x in byte_arr) + '}'


key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv


def xor_payload(converted_dll):
    # todo: add xor decryption operation to Loader
    # xor_dll = bytearray()
    # key_c = 0
    # for dll_b in converted_dll:
    #     if key_c > 15:
    #         key_c = 0
    #     xor_dll.append(dll_b ^ iv[key_c])
    #     key_c = + 1

    return converted_dll


def encrypt(uuids):
    encrypted_uuids = []
    for uuid in uuids:
        clean_uuid = uuid.strip('"')
        ct_bytes = cipher.encrypt(pad(
            bytes(clean_uuid, encoding='utf-8'),
            AES.block_size
        ))
        encrypted_uuids.append(generate_byte_file_string(ct_bytes))

    return (
        generate_byte_file_string(key),
        generate_byte_file_string(iv),
        encrypted_uuids
    )
