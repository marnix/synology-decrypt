import pyaes
import hashlib
from passlib.utils.pbkdf2 import pbkdf1
import struct


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


def decrypted_with_password(ciphertext, password):
        AES_KEY_SIZE_BITS = 256
        AES_IV_LENGTH_BYTES = 16
        (key,iv) = _openssl_kdf('md5', password, b'', AES_KEY_SIZE_BITS//8, AES_IV_LENGTH_BYTES)
        aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
        decrypter = pyaes.Decrypter(aes)
        decrypted = decrypter.feed(ciphertext)
        decrypted += decrypter.feed()
        return decrypted


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
                return _continue_read_dict_from(f)
        elif header_byte == 0x40:
                return None
        elif header_byte == 0x11:
                return _continue_read_bytes_from(f)
        elif header_byte == 0x10:
                return _continue_read_string_from(f)
        elif header_byte == 0x01:
                return _continue_read_int_from(f)
        else:
                assert False, 'header_byte should not be ' + ("0x%02X" % header_byte)

def _continue_read_dict_from(f):
        result = {}
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
        assert length == 1, 'currently only integers of 1 byte supported: endianness is unknown'
        return ord(f.read(1))


def decode_csenc_stream(f):
        MAGIC = b'__CLOUDSYNC_ENC__'

        s = f.read(len(MAGIC))
        assert s == MAGIC, 'magic should not be ' + str(s) + ' but ' + str(MAGIC)
        s = f.read(32)
        magic_hash = hashlib.md5(MAGIC).hexdigest().encode('ascii')
        assert s == magic_hash, 'magic hash should not be ' + str(s) + ' but ' + str(magic_hash)

        metadata = {}
        data = b''
        for obj in _read_objects_from(f):
                assert isinstance(obj, dict)
                if obj['type'] == 'metadata':
                        for (k,v) in obj.items():
                                if k != 'type': yield (True, (k,v))
                elif obj['type'] == 'data':
                        yield (False, obj['data'])
