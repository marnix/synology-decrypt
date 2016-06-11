import syndecrypt
import collections

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
                s = syndecrypt.decode_csenc_stream(f)
                assert next(s) == ('compress', 1)
                assert next(s) == ('digest', 'md5')
                assert next(s) == ('enc_key1', 'f662PyjwrkzR61qSRHyBEVkXVd7STUpV6o7IrJs+m8gN1haqmBtMzLvq2/Gj134r')
                assert next(s) == ('enc_key2', 'ovVar7Zpi0HVPZ3CGmXRBhp4l1Q1BNNo0/uYfdwSg1GDD/MXNSMXcuAf65pYObUQsu4aCQc82LldLINkUSFyoPYUDe5YKh4Fv3993YQ7CPYk5RrWem2CGntdjmS1J5KV9YHa7bF2l6wMT2FiFvfd+/3Pikadb/fqOC/hN5hx2kA2c5n3FltCGehhfW97Bb3aLEZaOJ8rpoPuHDIa6yxhstCHrajnb0870KprqSfFZUdin1G1hqpwJ+1gm7CmFkjKA6QqMD5dx7bru69g98VwrqYqGmYR3lmJuMI0wJn7WwbciWCOQV5fnfMMxiAiZ0DK1fseqWxMIYUk3lVOcAA3KA==')
                assert next(s) == ('encrypt', 1)
                assert next(s) == ('file_name', 'single-line.txt')
                assert next(s) == ('key1_hash', '4ZF3pd4Y17c7cf0f016aada3f8398d22c8708d8649')
                assert next(s) == ('key2_hash', 'Hs2fAqiRaTb73da9c06e2b824dc3a9935ae71bdd14')
                assert next(s) == ('session_key_hash', 'jM41by6vAd517830d42bfb52eae9b58cd41eac95b0')
                assert next(s) == ('version', collections.OrderedDict([('major', 1), ('minor', 0)]))
                (k,v) = next(s)
                assert k == None and isinstance(v, bytes) # a chunk of encrypted data
                assert next(s) == ('file_md5', 'e45f14e62971070603ff27c2bb05f5a4')
