"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt (-p <password-file> | -k <private.pem>) -O <directory> <encrypted-file>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory
  -p <password-file> --password-file=<password-file>
                           The file containing the decryption password
  -k <private.pem> --key-file=<private.pem>
                           The file containing the decryption private key
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import os
import logging

import syndecrypt.files as files
import syndecrypt.util as util

arguments = docopt.docopt(__doc__)

password_file_name = arguments['--password-file']
if password_file_name != None:
        password = util._binary_contents_of(password_file_name).strip()
else: password = None

private_key_file_name = arguments['--key-file']
if private_key_file_name != None:
        private_key = util._binary_contents_of(private_key_file_name)
else: private_key = None

output_dir = arguments['--output-directory']

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(levelname)s: %(message)s')

for f in arguments['<encrypted-file>']:
        files.decrypt_file(f, os.path.join(output_dir, f), password=password, private_key=private_key)
