from sys import argv
from shutil import copyfile
import subprocess
"""Warning! This file is autistic"""

dll_path = argv[1]
output_header_path = '..\\Loader\\Payload.h'

subprocess.run([
    'python',
    'PE2SH2UUID.py',
    '-f main',
    '-fh',
    str(dll_path)
])

header_path = dll_path.replace('.dll', '.h')
copyfile(header_path, output_header_path)
