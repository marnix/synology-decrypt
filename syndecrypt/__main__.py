"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt (-p <password-file> | -k <private.pem> -l <public.pem>) -O <directory> <encrypted-file>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory
  -p <password-file> --password-file=<password-file>
                           The file containing the decryption password
  -k <private.pem> --private-key-file=<private.pem>
                           The file containing the decryption private key
  -l <private.pem> --public-key-file=<public.pem>
                           The file containing the decryption public key
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import os
import logging

#import syndecrypt.files as files
import files
#import syndecrypt.util as util
import util

arguments = docopt.docopt(__doc__)

password_file_name = arguments['--password-file']
if password_file_name != None:
        password = util._binary_contents_of(password_file_name).strip()
else: password = None

private_key_file_name = arguments['--private-key-file']
if private_key_file_name != None:
        private_key = util._binary_contents_of(private_key_file_name)
else: private_key = None

public_key_file_name = arguments['--public-key-file']
if public_key_file_name != None:
        public_key = util._binary_contents_of(public_key_file_name)
else: public_key = None

output_dir = arguments['--output-directory']
output_dir = os.path.abspath(output_dir)

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(levelname)s: %(message)s')

for f in arguments['<encrypted-file>']:
        ff = os.path.abspath(f)
        fp = os.path.basename(ff)
        files.decrypt_file(ff, os.path.join(output_dir, fp), password=password, private_key=private_key, public_key=public_key)
