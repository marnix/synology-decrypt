import pyaes
import hashlib
from passlib.utils.pbkdf2 import pbkdf1


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
