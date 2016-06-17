from __future__ import print_function
import os
import logging

LOGGER=logging.getLogger(__name__)

def decrypt_file(input_file_name, output_file_name):
        if not os.path.exists(input_file_name):
                LOGGER.warn('skipping decryption of "%s": encrypted input file does not exist',
                        input_file_name
                )
                return
        if os.path.exists(output_file_name):
                LOGGER.warn('skipping decryption of "%s": chosen output file "%s" already exists',
                        input_file_name, output_file_name
                )
                return
        LOGGER.info('decrypting "%s" to "%s"', input_file_name, output_file_name)
