#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MAGIC = "LEAF".encode('utf-8')
CHECK_WORLD = "LEAFNOTE IS AWESOME".encode('utf-8')
CODE_CHECK_WORLD = 0x01
CODE_AES_PASSWORD = 0x02
CODE_CONTENT = 0x03

class FileSection:
    def __init__(self, code: int, length: int, data: bytes):
        self.code = code
        self.length = length
        self.data = data

def bytes_to_int(b: bytes) -> int:
    # Change bytes to int.
    return int.from_bytes(b, byteorder='big')

def get_encrypt_sections(data: bytes) -> Dict[int, FileSection]:
    # Get encypted file sections.
    sections = {}
    index = len(MAGIC)

    while index < len(data):
        code = data[index]
        length = bytes_to_int(data[index + 1:index + 5])
        body = data[index + 5:index + 5 + length]
        sections[code] = FileSection(code, length, body)

        index += 1 + 4 + length

    return sections

def get_encrypt_aes_key_and_iv(code: str) -> tuple[str, str]:
    # Get AES encrypt Key and IV.
    passcode = code
    while len(passcode) < 48:
        passcode += code

    key = passcode[0:32]
    iv = passcode[32:48]

    return key, iv

def encrypt_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    # AES encrypt.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return encrypted

def decrypt_aes(data: bytes, key: bytes, iv: bytes) -> str:
    # AES decrypt.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size).decode('utf-8')

def decrypt_note(path: str, code: str):
    """Decrypt encrypted file."""

    # Read file to bytes.
    with open(path, "rb") as f:
        data = f.read()

    # Check magic number.
    magic = data[:len(MAGIC)]
    if magic != MAGIC:
        raise RuntimeError("magic not match")

    # Get data sections.
    sections = get_encrypt_sections(data)

    # Check key.
    check_section: FileSection = sections.get(CODE_CHECK_WORLD)
    if check_section is None:
        raise RuntimeError("file format error")

    key, iv = get_encrypt_aes_key_and_iv(code)
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    check_word_bytes = encrypt_aes(CHECK_WORLD, key_bytes, iv_bytes)
    if check_word_bytes is None or check_section.data != check_word_bytes:
        raise RuntimeError("encrypt key error")

    # Get content section.
    content_section: FileSection = sections.get(CODE_CONTENT)
    if content_section is None:
        raise RuntimeError("note body not found")

    decrypted = decrypt_aes(content_section.data, key_bytes, iv_bytes)
    if decrypted is None:
        raise RuntimeError("encrypt file io")

    print(decrypted)

# Begin Here.
decrypt_note('YOUR-PATH-OF-NONE', 'YOUR-ENCRYPTION-KEY')    
