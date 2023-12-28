#!/usr/bin/env python

from struct import *
import hashlib
import os
import sys

with open(sys.argv[1], 'br+') as partFile:
  imageSize = (os.stat(sys.argv[2]).st_size + 0xFFFF) & ~0xFFFF
  adjust = None
  signature = hashlib.md5()
  while True:
    data = partFile.read(32)
    entry = list(unpack('<HBBII16sI', data))
    if entry[0] == 0x50AA:
      if adjust:
        # If the previous partition was changed in size, adjust the
        # next one to match.
        print(f'Adjusting factory partition by {adjust} bytes')
        entry[3] += adjust
        entry[4] -= adjust
        adjust = None
      elif entry[1] == 0 and entry[2] == 0:
        # This is the main "factory" app
        if entry[4] == imageSize:
          print('Partition size is already optimal')
          exit(0)
        adjust = imageSize - entry[4]
        entry[4] = imageSize
      partFile.seek(-32, 1)
      data = pack('<HBBII16sI', *entry)
      partFile.write(data)
      signature.update(data)
    elif entry[0] == 0xEBEB:
      # This is the MD5 checksum
      entry = unpack('<H14s16s', data)
      partFile.seek(-16, 1)
      partFile.write(signature.digest())
      exit(0)