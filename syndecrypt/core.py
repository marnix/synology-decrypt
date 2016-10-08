import syndecrypt.util as util
from syndecrypt.util import switch

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib

import logging
import struct
from collections import OrderedDict
import base64

LOGGER=logging.getLogger(__name__)

# Thanks to http://security.stackexchange.com/a/117654/3617,
# this is the algorithm by which 'openssl enc' generates
# a key and an iv from a password.
#
# Sources for this algorithm:
# - https://github.com/openssl/openssl/blob/OpenSSL_1_0_1m/apps/enc.c#L540
#   and https://github.com/openssl/openssl/blob/OpenSSL_1_0_1m/apps/enc.c#L347
# - https://github.com/openssl/openssl/blob/OpenSSL_1_0_1m/crypto/evp/evp_key.c#L119
#   and https://www.openssl.org/docs/manmaster/crypto/EVP_BytesToKey.html
#
# Synology Cloud Sync encryption/decryption uses the same
# algorithm to generate key+iv from the password.

# pwd and salt must be bytes objects
def _openssl_kdf(algo, pwd, salt, key_size, iv_size):
    temp = b''

    fd = temp
    while len(fd) < key_size + iv_size:
        temp = _hasher(algo, temp + pwd + salt)
        fd += temp

    key = fd[0:key_size]
    iv = fd[key_size:key_size+iv_size]

    return key, iv

def _hasher(algo, data):
    h = hashlib.new(algo)
    h.update(data)
    return h.digest()

# From pyaes, since pycrypto does not implement padding

def strip_PKCS7_padding(data):
    if len(data) % 16 != 0:
        raise ValueError("invalid length")
    pad = bytearray(data)[-1]
    if pad > 16:
        raise ValueError("invalid padding byte at end of " + repr(data))
    for i in range(-pad, 0):
        if bytearray(data)[i] != pad:
            raise ValueError("invalid padding byte at " + str(i) + " in " + repr(data))
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

        for obj in _read_objects_from(f):
                assert isinstance(obj, dict)
                if obj['type'] == 'metadata':
                        for (k,v) in obj.items():
                                if k != 'type': yield (k,v)
                elif obj['type'] == 'data':
                        yield (None, obj['data'])


def decrypt_stream(instream, outstream, password=None, private_key=None):

        session_key = None
        decryptor = None
        decrypt_stream.md5_digestor = None # special kind of local variable...
        expected_md5_digest = None

        def outstream_writer_and_md5_digestor(decompressed_chunk):
                outstream.write(decompressed_chunk)
                if decrypt_stream.md5_digestor != None:
                        decrypt_stream.md5_digestor.update(decompressed_chunk)

        with util.Lz4Decompressor(decompressed_chunk_handler=outstream_writer_and_md5_digestor) as decompressor:
                for (key,value) in decode_csenc_stream(instream):
                        for case in switch(key):
                                if case('digest'):
                                        if value != 'md5':
                                                LOGGER.warning('found unexpected digest "%s": cannot verify checksum', value)
                                        decrypt_stream.md5_digestor = hashlib.md5()
                                        break
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
                                if case('key1_hash'):
                                        if password != None:
                                                actual_password_hash = salted_hash_of(value[:10], password)
                                                if value != actual_password_hash:
                                                        LOGGER.warning('found key1_hash %s but expected %s', actual_password_hash, value)
                                        break
                                if case('key2_hash'):
                                        # TODO: verify some public/private key pair hash here
                                        break
                                if case('session_key_hash'):
                                        if session_key != None:
                                                actual_session_key_hash = salted_hash_of(value[:10], session_key)
                                                if value != actual_session_key_hash:
                                                        LOGGER.warning('found session_key_hash %s but expected %s', actual_session_key_hash, value)
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
                                        decrypted_chunk = decryptor_update(decryptor, value)
                                        decompressor.write(decrypted_chunk)
                                        break
                                if case('file_md5'):
                                        expected_md5_digest = value
                                        break

        if decrypt_stream.md5_digestor != None and expected_md5_digest != None:
                actual_md5_digest = decrypt_stream.md5_digestor.hexdigest()
                if actual_md5_digest != expected_md5_digest:
                        raise Exception('expected md5 digest %s but found %s', expected_md5_digest, actual_md5_digest)
