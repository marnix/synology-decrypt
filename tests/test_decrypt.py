from __future__ import print_function

import syndecrypt.core as core
import syndecrypt.util as util
import collections

from assertpy import assert_that
import base64
import binascii
import io
import logging

LOGGER=logging.getLogger(__name__)

PASSWORD=util._binary_contents_of('tests/testfiles-secrets/password.txt')
PRIVATE_KEY=util._binary_contents_of('tests/testfiles-secrets/private.pem')


def test_decode_int():
        assert core._continue_read_int_from(io.BytesIO(b'\x00')) == 0
        assert core._continue_read_int_from(io.BytesIO(b'\x01\x02')) == 2
        assert core._continue_read_int_from(io.BytesIO(b'\x01\x82')) == 128 + 2
        assert core._continue_read_int_from(io.BytesIO(b'\x02\x80\x02')) == 32768 + 2



def test_keyiv_v1():
        assert core._csenc_pbkdf(b'buJx9/y9fV', b'') == (
                binascii.unhexlify('4F3E66EF6D006CFF64B332226E8F109DA8D0441F966FBA2948F55934F92AACB8'),
                binascii.unhexlify('3ADCF6A17E01689567E1C6C6856112B1')
                )

def test_keyiv_v3():
        assert core._csenc_pbkdf(b'buJx9/y9fV', b'DXzp4VKu') == (
                binascii.unhexlify('74DCF4660DA7FDE6B18B88E48D72D7E6E9EC48D13995D420FE3CE7DF71E62B04'),
                binascii.unhexlify('95487A753CD99A7D8E8B19280455E151')
                )



def test_decrypt_enc_key1_v1():
        """
        Test that we can do the equivalent of

          $ echo 'f662PyjwrkzR61qSRHyBEVkXVd7STUpV6o7IrJs+m8gN1haqmBtMzLvq2/Gj134r' | openssl enc -aes256 -d -a -pass pass:'buJx9/y9fV' -nosalt
          BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6
        """

        enc_key1 = b'f662PyjwrkzR61qSRHyBEVkXVd7STUpV6o7IrJs+m8gN1haqmBtMzLvq2/Gj134r'
        enc_key1_binary = base64.b64decode(enc_key1)
        assert core.decrypted_with_password(enc_key1_binary, PASSWORD, salt=b'') == b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'

def test_decrypt_enc_key1_v3():
        """
        Test that we can do the equivalent of the following, except with
        an OpenSSL key/iv algorithm that hashes 1000 times instead of
        OpenSSL's 1.

          $ echo '6Gbow/t0ltbdXw2L79IS41HTVY7ffwl7vlmUs4CCOmtoqSIdxDxTcmt2cmjE38AfkvmTg0BwcK5WIsEMJwA81NS8vaHUv74D9XhPXMRclbM=' | openssl enc -aes256 -d -a -pass pass:'buJx9/y9fV'
          EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215
        """

        salt = b'DXzp4VKu'
        enc_key1 = b'6Gbow/t0ltbdXw2L79IS41HTVY7ffwl7vlmUs4CCOmtoqSIdxDxTcmt2cmjE38AfkvmTg0BwcK5WIsEMJwA81NS8vaHUv74D9XhPXMRclbM='
        enc_key1_binary = base64.b64decode(enc_key1)
        assert core.decrypted_with_password(enc_key1_binary, PASSWORD, salt=salt) == b'EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215'

def test_decrypt_enc_key2_v1():
        """
        Test that we can do the equivalent of

          $ echo 'ovVar7Zpi0HVPZ3CGmXRBhp4l1Q1BNNo0/uYfdwSg1GDD/MXNSMXcuAf65pYObUQsu4aCQc82LldLINkUSFyoPYUDe5YKh4Fv3993YQ7CPYk5RrWem2CGntdjmS1J5KV9YHa7bF2l6wMT2FiFvfd+/3Pikadb/fqOC/hN5hx2kA2c5n3FltCGehhfW97Bb3aLEZaOJ8rpoPuHDIa6yxhstCHrajnb0870KprqSfFZUdin1G1hqpwJ+1gm7CmFkjKA6QqMD5dx7bru69g98VwrqYqGmYR3lmJuMI0wJn7WwbciWCOQV5fnfMMxiAiZ0DK1fseqWxMIYUk3lVOcAA3KA==' \
              | base64 -d | openssl rsautl -decrypt -inkey tests/testfiles-secrets/private.pem -oaep
          BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6
        """
        enc_key2 = b'ovVar7Zpi0HVPZ3CGmXRBhp4l1Q1BNNo0/uYfdwSg1GDD/MXNSMXcuAf65pYObUQsu4aCQc82LldLINkUSFyoPYUDe5YKh4Fv3993YQ7CPYk5RrWem2CGntdjmS1J5KV9YHa7bF2l6wMT2FiFvfd+/3Pikadb/fqOC/hN5hx2kA2c5n3FltCGehhfW97Bb3aLEZaOJ8rpoPuHDIa6yxhstCHrajnb0870KprqSfFZUdin1G1hqpwJ+1gm7CmFkjKA6QqMD5dx7bru69g98VwrqYqGmYR3lmJuMI0wJn7WwbciWCOQV5fnfMMxiAiZ0DK1fseqWxMIYUk3lVOcAA3KA=='
        enc_key2_binary = base64.b64decode(enc_key2)

        assert core.decrypted_with_private_key(enc_key2_binary, PRIVATE_KEY) == b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'

def test_decrypt_enc_key2_v3():
        """
        Test that we can do the equivalent of

          $ echo 'E+WD7iAnJibEDt6wtzoJq34MIu4s0sUSOnkCJcr85LcnI9hI6M2RQsQvhCZsWbxW0OXltkoVNvJX1UUVi13NyyEdNax1lPAmgGig8dEKAt0hEH8fNHS0N4A5xNwtFzqDKlFw5Jfiqq1Hw+yXzZ5PXz0Z1I3ORa/JwfK1L4lp3wDGiGrR1CVxHCgjm+Ncg9yM7UAAFydVPH8AenzOEKFyGcbmv6vibHNSGraBTrxEZBsxu1bnbH4eW5jpNNpoyjib1F7W4RE2qSI+DU7F4tij8GiePuMyihdg5SjMerEcvOQWDqHGsQ6IbXeYnGgZQ+bPd7EONsI4uYrUgENKId73Zw==' \
              | base64 -d | openssl rsautl -decrypt -inkey tests/testfiles-secrets/private.pem -oaep
          EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215
        """
        enc_key2 = b'E+WD7iAnJibEDt6wtzoJq34MIu4s0sUSOnkCJcr85LcnI9hI6M2RQsQvhCZsWbxW0OXltkoVNvJX1UUVi13NyyEdNax1lPAmgGig8dEKAt0hEH8fNHS0N4A5xNwtFzqDKlFw5Jfiqq1Hw+yXzZ5PXz0Z1I3ORa/JwfK1L4lp3wDGiGrR1CVxHCgjm+Ncg9yM7UAAFydVPH8AenzOEKFyGcbmv6vibHNSGraBTrxEZBsxu1bnbH4eW5jpNNpoyjib1F7W4RE2qSI+DU7F4tij8GiePuMyihdg5SjMerEcvOQWDqHGsQ6IbXeYnGgZQ+bPd7EONsI4uYrUgENKId73Zw=='
        enc_key2_binary = base64.b64decode(enc_key2)

        assert core.decrypted_with_private_key(enc_key2_binary, PRIVATE_KEY) == b'EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215'


def test_salted_hash_v1():
        session_key = b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'
        session_key_hash = 'jM41by6vAd517830d42bfb52eae9b58cd41eac95b0'
        assert core.salted_hash_of(session_key_hash[:10], session_key) == session_key_hash
        assert core.is_salted_hash_correct(session_key_hash, session_key)

        password_hash = '4ZF3pd4Y17c7cf0f016aada3f8398d22c8708d8649'
        assert core.salted_hash_of(password_hash[:10], PASSWORD) == password_hash
        assert core.is_salted_hash_correct(password_hash, PASSWORD)

def test_salted_hash_v3():
        session_key = b'EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215'
        session_key_hash = 'ofQaqQeFxY2b95456e59bf119d04cef906dd8f8046'
        assert core.salted_hash_of(session_key_hash[:10], session_key) == session_key_hash
        assert core.is_salted_hash_correct(session_key_hash, session_key)

        password_hash = 'uTVhxSKK1Da958d45e7a65a63f30cf527984e800f3'
        assert core.salted_hash_of(password_hash[:10], PASSWORD) == password_hash
        assert core.is_salted_hash_correct(password_hash, PASSWORD)


def lz4_uncompress(compressed_data):
        result = io.BytesIO()
        with util.Lz4Decompressor(decompressed_chunk_handler=result.write) as decompressor:
                decompressor.write(compressed_data)
        return result.getvalue()

def test_decode_single_line_file_v1():
        with open('tests/testfiles-v1/csenc/single-line.txt', 'rb') as f:
                s = core.decode_csenc_stream(f)
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
                (none, data) = next(s)
                assert none == None and isinstance(data, bytes) # a chunk of encrypted compressed data
                assert next(s) == ('file_md5', 'e45f14e62971070603ff27c2bb05f5a4')

                session_key = b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'
                decrypted_compressed_data = core.decrypted_with_password(data, session_key, salt=b'')
                decrypted_uncompressed_data = lz4_uncompress(decrypted_compressed_data)
                assert decrypted_uncompressed_data == b'Just a single line, no newline character at the end...'


def test_decode_single_line_file_v3():
        with open('tests/testfiles-v3/csenc/ssingle-line.txt', 'rb') as f:
                s = core.decode_csenc_stream(f)
                assert next(s) == ('compress', 1)
                assert next(s) == ('digest', 'md5')
                assert next(s) == ('enc_key1', '6Gbow/t0ltbdXw2L79IS41HTVY7ffwl7vlmUs4CCOmtoqSIdxDxTcmt2cmjE38AfkvmTg0BwcK5WIsEMJwA81NS8vaHUv74D9XhPXMRclbM=')
                assert next(s) == ('enc_key2', 'E+WD7iAnJibEDt6wtzoJq34MIu4s0sUSOnkCJcr85LcnI9hI6M2RQsQvhCZsWbxW0OXltkoVNvJX1UUVi13NyyEdNax1lPAmgGig8dEKAt0hEH8fNHS0N4A5xNwtFzqDKlFw5Jfiqq1Hw+yXzZ5PXz0Z1I3ORa/JwfK1L4lp3wDGiGrR1CVxHCgjm+Ncg9yM7UAAFydVPH8AenzOEKFyGcbmv6vibHNSGraBTrxEZBsxu1bnbH4eW5jpNNpoyjib1F7W4RE2qSI+DU7F4tij8GiePuMyihdg5SjMerEcvOQWDqHGsQ6IbXeYnGgZQ+bPd7EONsI4uYrUgENKId73Zw==')
                assert next(s) == ('encrypt', 1)
                assert next(s) == ('file_name', 'ssingle-line.txt')
                assert next(s) == ('key1_hash', 'uTVhxSKK1Da958d45e7a65a63f30cf527984e800f3')
                assert next(s) == ('key2_hash', 'vNPKBAbNC9207d495491d14cfbb2a960274ff65796')
                assert next(s) == ('salt', 'DXzp4VKu')
                assert next(s) == ('session_key_hash', 'ofQaqQeFxY2b95456e59bf119d04cef906dd8f8046')
                assert next(s) == ('version', collections.OrderedDict([('major', 3), ('minor', 0)]))
                (none, data) = next(s)
                assert none == None and isinstance(data, bytes) # a chunk of encrypted compressed data
                assert next(s) == ('file_md5', 'e45f14e62971070603ff27c2bb05f5a4')

                session_key = b'EA23EB5F36B9008AC73498A8FC53884D1D7EFBA052F902F44B44D40409CBC215'
                decrypted_compressed_data = core.decrypted_with_password(data, session_key, salt=b'DXzp4VKu')
                decrypted_uncompressed_data = lz4_uncompress(decrypted_compressed_data)
                assert decrypted_uncompressed_data == b'Just a single line, no newline character at the end...'


def test_decrypt_single_line_stream_with_password_v1():
        outstream = io.BytesIO()
        with open('tests/testfiles-v1/csenc/single-line.txt', 'rb') as f:
                core.decrypt_stream(f, outstream, password=PASSWORD)
        assert outstream.getvalue() == b'Just a single line, no newline character at the end...'

def test_decrypt_single_line_stream_with_password_v3():
        outstream = io.BytesIO()
        with open('tests/testfiles-v3/csenc/ssingle-line.txt', 'rb') as f:
                core.decrypt_stream(f, outstream, password=PASSWORD)
        assert outstream.getvalue() == b'Just a single line, no newline character at the end...'

def test_decrypt_single_line_stream_with_private_key_v1():
        outstream = io.BytesIO()
        with open('tests/testfiles-v1/csenc/single-line.txt', 'rb') as f:
                core.decrypt_stream(f, outstream, private_key=PRIVATE_KEY)
        assert outstream.getvalue() == b'Just a single line, no newline character at the end...'

def test_decrypt_single_line_stream_with_private_key_v3():
        outstream = io.BytesIO()
        with open('tests/testfiles-v3/csenc/ssingle-line.txt', 'rb') as f:
                core.decrypt_stream(f, outstream, private_key=PRIVATE_KEY)
        assert outstream.getvalue() == b'Just a single line, no newline character at the end...'

def test_decrypt_single_line_stream_fails_without_key():
        outstream = io.BytesIO()
        try:
                with open('tests/testfiles-v1/csenc/single-line.txt', 'rb') as f:
                        core.decrypt_stream(f, outstream)
                assert False, 'expected exception'
        except Exception as e:
                assert_that(e.args[0]).matches('not enough information to decrypt')
