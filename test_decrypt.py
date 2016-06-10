import syndecrypt

import assertpy
import base64


def binary_contents_of(file_name):
        with open(file_name, 'rb') as f: return f.read()

PASSWORD=binary_contents_of('testfiles-secrets/password.txt')


def test_decrypt_enc_key1():
        """
        Test that we can do the equivalent of

          $ echo 'f662PyjwrkzR61qSRHyBEVkXVd7STUpV6o7IrJs+m8gN1haqmBtMzLvq2/Gj134r' | openssl enc -aes256 -d -a -pass pass:'buJx9/y9fV' -nosalt
          BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6
        """

        enc_key1 = b'f662PyjwrkzR61qSRHyBEVkXVd7STUpV6o7IrJs+m8gN1haqmBtMzLvq2/Gj134r'
        enc_key1_binary = base64.b64decode(enc_key1)
        assert syndecrypt.decrypted_with_password(enc_key1_binary, PASSWORD) == b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'


def test_decode_single_line_file():
        with open('testfiles-csenc/single-line.txt', 'rb') as f:
                for (is_meta, value) in syndecrypt.decode_csenc_stream(f):
                        if is_meta: print(value[0], ':', value[1])
                        else: pass
