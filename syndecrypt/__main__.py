"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt (-p <password-file> | -k <private.pem>) (-w <workers>) -O <directory> <encrypted-folder>
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory
  -p <password-file> --password-file=<password-file>
                           The file containing the decryption password
  -k <private.pem> --key-file=<private.pem>
                           The file containing the decryption private key
  -w <workers> --workers=<workers>
                          Number of processes to use
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import logging
import os
from concurrent.futures import ProcessPoolExecutor, wait

import docopt

import syndecrypt.util as util
from syndecrypt.decrypt import decrypt_file

arguments = docopt.docopt(__doc__)

password_file_name = arguments["--password-file"]
if password_file_name != None:
    password = util._binary_contents_of(password_file_name).strip()
else:
    password = None

private_key_file_name = arguments["--key-file"]
if private_key_file_name != None:
    private_key = util._binary_contents_of(private_key_file_name)
else:
    private_key = None

output_dir = arguments["--output-directory"]
output_dir = os.path.join(os.curdir, output_dir)

logging.getLogger().setLevel(logging.INFO)
logging.basicConfig(format="%(levelname)s: %(message)s")

jobs = []
encrypted_dir = arguments["<encrypted-folder>"]
with ProcessPoolExecutor(int(arguments["--workers"])) as pool:
    for path, _, files in os.walk(encrypted_dir):
        path_decrypt = path.replace(encrypted_dir, output_dir)
        for f in files:
            source = os.path.join(path, f)
            output = os.path.join(path_decrypt, f)
            fut = pool.submit(
                decrypt_file, source, output, password=password, private_key=private_key
            )
            jobs.append(fut)
    wait(jobs)
