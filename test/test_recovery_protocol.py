#!/usr/bin/env python3
import base64
import hashlib
import hmac
import struct
import unicodedata


def text(value):
    return unicodedata.normalize('NFC', value).encode('utf-8')


def field(tag, value):
    return bytes([tag]) + struct.pack('>I', len(value)) + value


seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
files = []
for name, content in [('z.txt', b'z'), ('a.txt', b'alpha')]:
    files.append((text(name), hashlib.sha512(content).digest(), len(content)))
files.sort(key=lambda item: (item[0], item[1]))

canonical = b'SecurityUtilsRecovery' + struct.pack('>I', 1) + field(1, text('snapshot-α'))
for tag, answer in enumerate(('first', '', 'third'), start=2):
    canonical += field(tag, text(answer))
for name, digest, size in files:
    canonical += field(5, field(1, name) + field(2, struct.pack('>I', size)) + field(3, digest))

salt = hashlib.sha512(canonical).digest()
prk = hmac.new(salt, seed, hashlib.sha512).digest()
okm = hmac.new(prk, b'Security Utils Recovery Key v1' + b'\x01', hashlib.sha512).digest()[:32]
credential = base64.urlsafe_b64encode(okm).rstrip(b'=').decode('ascii')

assert credential == 'AZ2FB-zw4kL7CjEHFlY5RwmuhhhGahrNKWaYhnjgcRw'
print('Independent Python Recovery Protocol v1 vector passed')
