import syndecrypt.util as util
from syndecrypt.util import switch

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from passlib.utils.pbkdf2 import pbkdf1

import logging
import struct
from collections import OrderedDict
import base64

LOGGER=logging.getLogger(__name__)

# Thanks to http://security.stackexchange.com/a/117654/3617,
# this is the algorithm by which 'openssl enc' generates
# a key and an iv from a password.
#
# Synology Cloud Synd encryption/decryption uses the same
# algorithm to generate key+iv from the password.

# pwd and salt must be bytes objects
def _openssl_kdf(algo, pwd, salt, key_size, iv_size):
    if algo == 'md5':
        temp = pbkdf1(pwd, salt, 1, 16, 'md5')
    else:
        temp = b''

    fd = temp
    while len(fd) < key_size + iv_size:
        temp = _hasher(algo, temp + pwd + salt)
        fd += temp

    key = fd[0:key_size]
    iv = fd[key_size:key_size+iv_size]

    return key, iv

def _hasher(algo, data):
    hashes = {'md5': hashlib.md5, 'sha256': hashlib.sha256, 'sha512': hashlib.sha512}
    h = hashes[algo]()
    h.update(data)
    return h.digest()

# From pyaes, since pycrypto does not implement padding

def strip_PKCS7_padding(data):
    if len(data) % 16 != 0:
        raise ValueError("invalid length")
    pad = bytearray(data)[-1]
    if pad > 16:
        raise ValueError("invalid padding byte")
    return data[:-pad]


def decrypted_with_password(ciphertext, password):
        decryptor = _decryptor_with_keyiv(_csenc_pbkdf(password))
        plaintext = decryptor_update(decryptor, ciphertext)
        return plaintext

def decryptor_with_password(password):
        return _decryptor_with_keyiv(_csenc_pbkdf(password))

def _csenc_pbkdf(password):
        AES_KEY_SIZE_BITS = 256
        AES_IV_LENGTH_BYTES = AES.block_size
        assert AES_IV_LENGTH_BYTES == 16
        (key,iv) = _openssl_kdf('md5', password, b'', AES_KEY_SIZE_BITS//8, AES_IV_LENGTH_BYTES)
        return (key,iv)

def _decryptor_with_keyiv(key_iv_pair):
        (key,iv) = key_iv_pair
        return AES.new(key, AES.MODE_CBC, iv)

def decryptor_update(decryptor, ciphertext):
        return strip_PKCS7_padding(decryptor.decrypt(ciphertext))

def decrypted_with_private_key(ciphertext, private_key):
        return PKCS1_OAEP.new(RSA.importKey(private_key)).decrypt(ciphertext)


def salted_hash_of(salt, data):
        m = hashlib.md5()
        m.update(salt.encode('ascii'))
        m.update(data)
        return salt + m.hexdigest()

def is_salted_hash_correct(salted_hash, data):
        return salted_hash_of(salted_hash[:10], data) == salted_hash

def _read_objects_from(f):
        result = []
        while True:
                obj = _read_object_from(f)
                if obj == None: break
                result += [obj]
        return result

def _read_object_from(f):
        s = f.read(1)
        if len(s) == 0: return None
        header_byte = bytearray(s)[0]
        if header_byte == 0x42:
                return _continue_read_ordered_dict_from(f)
        elif header_byte == 0x40:
                return None
        elif header_byte == 0x11:
                return _continue_read_bytes_from(f)
        elif header_byte == 0x10:
                return _continue_read_string_from(f)
        elif header_byte == 0x01:
                return _continue_read_int_from(f)
        else:
                raise Exception('unknown type byte ' + ("0x%02X" % header_byte))

def _continue_read_ordered_dict_from(f):
        result = OrderedDict()
        while True:
                key = _read_object_from(f)
                if key == None: break
                value = _read_object_from(f)
                result[key] = value
        return result

def _continue_read_bytes_from(f):
        s = f.read(2)
        length = struct.unpack('>H', s)[0]
        return f.read(length)

def _continue_read_string_from(f):
        return _continue_read_bytes_from(f).decode('utf-8')

def _continue_read_int_from(f):
        s = f.read(1)
        length = struct.unpack('>B', s)[0]
        if length > 1:
                LOGGER.warning('multi-byte number encountered; guessing it is big-endian')
        s = f.read(length)
        if length > 0 and bytes_to_bigendian_int(s[:1]) >= 128:
                LOGGER.warning('ambiguous number encountered; guessing it is positive')
        return bytes_to_bigendian_int(s) # big-endian integer, 'length' bytes

def bytes_to_bigendian_int(b):
        import binascii
        return int(binascii.hexlify(b), 16) if b != b'' else 0

def decode_csenc_stream(f):
        MAGIC = b'__CLOUDSYNC_ENC__'

        s = f.read(len(MAGIC))
        if s != MAGIC:
                LOGGER.error('magic should not be ' + str(s) + ' but ' + str(MAGIC))
        s = f.read(32)
        magic_hash = hashlib.md5(MAGIC).hexdigest().encode('ascii')
        if s != magic_hash:
                LOGGER.error('magic hash should not be ' + str(s) + ' but ' + str(magic_hash))

        metadata = {}
        data = b''
        for obj in _read_objects_from(f):
                assert isinstance(obj, dict)
                if obj['type'] == 'metadata':
                        for (k,v) in obj.items():
                                if k != 'type': yield (k,v)
                elif obj['type'] == 'data':
                        yield (None, obj['data'])


def lz4_uncompress(data):
        import tempfile
        import subprocess
        import os
        try:
                compr_file = tempfile.NamedTemporaryFile(delete=False)
                compr_file.write(data)
                compr_file.close()

                decompr_file = tempfile.NamedTemporaryFile(delete=True)
                decompr_file.close()

                subprocess.check_call(['lz4', '-d', compr_file.name, decompr_file.name])
                return util._binary_contents_of(decompr_file.name)
        finally:
                os.remove(compr_file.name)
                os.remove(decompr_file.name)


def decrypt_stream(instream, outstream, password=None, private_key=None):

        decryptor = None
        decrypted_data = b''

        for (key,value) in decode_csenc_stream(instream):
                for case in switch(key):
                        if case('enc_key1'):
                                if password != None:
                                        session_key = decrypted_with_password(base64.b64decode(value.encode('ascii')), password)
                                        decryptor = decryptor_with_password(session_key)
                                break
                        if case('enc_key2'):
                                if private_key != None:
                                        session_key = decrypted_with_private_key(base64.b64decode(value.encode('ascii')), private_key)
                                        decryptor = decryptor_with_password(session_key)
                                break
                        if case('version'):
                                expected_version_number = OrderedDict([('major',1),('minor',0)])
                                if value != expected_version_number:
                                        raise Exception('found version number ' + str(value) + \
                                                ' instead of expected ' + str(expected_version_number))
                                break
                        if case(None):
                                if decryptor == None:
                                        raise Exception('not enough information to decrypt data')
                                decrypted_data += decryptor_update(decryptor, value)
                                break

        outstream.write(lz4_uncompress(decrypted_data))
