#!/usr/bin/env python3
"""Generate synthetic protocol fixtures independently of the Rust implementation.

Requires Python cryptography only when regenerating fixtures; normal Rust builds
and tests use the checked-in bytes. No live credentials or vault data are used.
"""
import base64
import hashlib
import json
import pathlib
import struct
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding

ROOT = pathlib.Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
ROOT.mkdir(parents=True, exist_ok=True)
USERNAME, PASSWORD, ITERATIONS = 'user@example.com', '123456', 1000
KEY = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), USERNAME.encode(), ITERATIONS)
LOGIN_HASH = hashlib.pbkdf2_hmac('sha256', KEY, PASSWORD.encode(), 1).hex()
IV = bytes(range(16))


def crypt(value, key=KEY, cbc=True):
    value = value.encode() if isinstance(value, str) else value
    padder = padding.PKCS7(128).padder()
    value = padder.update(value) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(IV) if cbc else modes.ECB()).encryptor()
    data = enc.update(value) + enc.finalize()
    return b'!' + IV + data if cbc else data


def b64(value):
    if value.startswith(b'!'):
        return '!' + base64.b64encode(value[1:17]).decode() + '|' + base64.b64encode(value[17:]).decode()
    return base64.b64encode(value).decode()


def item(value):
    value = value.encode() if isinstance(value, str) else value
    return struct.pack('>I', len(value)) + value


def chunk(tag, value):
    return tag.encode() + item(value)


def account(aid, name, note=False, protect=False, key=KEY, cbc=True, encrypt_url=False):
    url = 'http://sn' if note else 'https://test-url.example.com/'
    extra = 'NoteType: Server\nHostname: foo.example.com\nUsername: test-note-user\nPassword: test-note-password' if note else ''
    values = [b''] * 36
    values[0] = aid
    values[1] = crypt(name, key, cbc)
    values[2] = crypt('test-group', key, cbc)
    values[3] = crypt(url, key) if encrypt_url else url.encode().hex()
    values[4] = crypt(extra, key, cbc)
    values[5] = '0'
    values[7] = crypt('' if note else 'xyz@example.com', key, cbc)
    values[8] = crypt('' if note else 'test-account-password', key, cbc)
    values[9] = '1' if protect else '0'
    values[12] = values[31] = 'skipped'
    values[27] = '0'
    return chunk('ACCT', b''.join(item(v) for v in values))


vault = chunk('LPAV', '1')
vault += account('0001', 'test-account', cbc=False)
vault += account('0002', 'test-note', note=True)
vault += account('0003', 'test-reprompt-account', protect=True)
vault += account('0004', 'test-reprompt-note', note=True, protect=True)
vault += chunk('ENDM', 'OK')
(ROOT / 'legacy_vault.bin').write_bytes(vault)

private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
public_der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
share_key = bytes(range(32, 64))
rsa_key = private.public_key().encrypt(share_key.hex().encode(), rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
share = b''.join(item(v) for v in ['s1', rsa_key.hex(), b64(crypt('Shared-Team', share_key)), '0'])
shared = chunk('LPAV', '7') + account('0001', 'personal') + chunk('SHAR', share)
shared += account('0005', 'shared-account', key=share_key, encrypt_url=True)
shared += chunk('ACFL', b''.join(item(v) for v in ['custom-field', 'text', crypt('custom-value', share_key), '0']))
shared += chunk('ENDM', 'OK')
(ROOT / 'shared_vault.bin').write_bytes(shared)

envelope = 'LastPassPrivateKey<' + private_der.hex() + '>LastPassPrivateKey'
metadata = {
    'username': USERNAME, 'password': PASSWORD, 'iterations': ITERATIONS,
    'key_hex': KEY.hex(), 'login_hash': LOGIN_HASH,
    'cbc': b64(crypt('synthetic cipher vector')),
    'ecb': b64(crypt('synthetic cipher vector', cbc=False)),
    'private_key_der_hex': private_der.hex(), 'public_key_der_hex': public_der.hex(),
    'private_key_v2': b64(crypt(envelope)),
    'share_key_hex': share_key.hex(),
}
# v1 private-key format uses the first 16 bytes of the vault key as its IV.
padder = padding.PKCS7(128).padder()
data = padder.update(envelope.encode()) + padder.finalize()
encryptor = Cipher(algorithms.AES(KEY), modes.CBC(KEY[:16])).encryptor()
metadata['private_key_v1'] = (encryptor.update(data) + encryptor.finalize()).hex()
(ROOT / 'vectors.json').write_text(json.dumps(metadata, indent=2) + '\n')
print('Generated three synthetic fixture files.')
