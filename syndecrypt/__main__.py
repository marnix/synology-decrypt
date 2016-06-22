"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt (-p <password> | -k <private.pem>) -O <directory> <encrypted-file>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory
  -p <password> --password=<password>
                           The decryption password
  -k <private.pem> --keyfile=<private.pem>
                           The decryption private key
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import os
import logging

import syndecrypt.files as files
import syndecrypt.util as util

arguments = docopt.docopt(__doc__)

password = arguments['--password']
if password != None:
        password = password.encode('ascii') # TODO: which encoding?

private_key_file_name = arguments['--keyfile']
if private_key_file_name != None:
        private_key = util._binary_contents_of(private_key_file_name)

output_dir = arguments['--output-directory']

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(levelname)s: %(message)s')

for f in arguments['<encrypted-file>']:
        files.decrypt_file(f, os.path.join(output_dir, f), password=password, private_key=private_key)
