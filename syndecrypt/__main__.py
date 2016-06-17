"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt -p <password> -O <directory> <encrypted-file>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory
  -p <password> --password=<password>
                           The decryption password
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import os
import logging

import files

arguments = docopt.docopt(__doc__)

password = arguments['--password']
output_dir = arguments['--output-directory']

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format='%(levelname)s: %(message)s')

for f in arguments['<encrypted-file>']:
        files.decrypt_file(f, os.path.join(output_dir, f))
