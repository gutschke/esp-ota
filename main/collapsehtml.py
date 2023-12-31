#!/usr/bin/env python

import sys
import re

with open(sys.argv[1], 'rt') as f:
  html = f.read()

# Substitute variables of the form ${XXX} with definitions from a
# user-provided file, such as "sdkconfig". This is useful to insert
# the project name into the embedded HTML file.
with open(sys.argv[2], 'rt') as f:
  config = { k: re.sub(r'^"(.*)"$', r'\1', v)
             for k, v in [ l.split('=', 1)
             for l in f.read().split('\n') if '=' in l] }

# Make a best effort to collapse all unnecessary white-space in our
# embedded HTML file. That saves space. But since we don't have a full
# HTML/CSS/SVG/JavaScript parser, we have to use heuristics to guess
# where white-space can safely be removed. This should work, but it might
# need tweaking, if we make substantial changes to our source file.
html = re.sub(r'\s//\s.*', '', html)
html = re.sub(r'^//\s.*', '', html)
html = re.sub(r'\s+', ' ', html)
html = re.sub(r'\s$', '', html)
html = re.sub(r'([^\w"\'])\s(\w)', r'\1\2', html)
html = re.sub(r'(\w)\s([^-.\w"\'])', r'\1\2', html)
html = re.sub(r'([^\w"\'])\s([^\w"\'])', r'\1\2', html)
html = re.sub(r'\s/>', r'/>', html)
html = re.sub(r'\$\{([^}]+)\}', lambda m: config[m[1]], html)

with open(sys.argv[3], "wt") as f:
  f.write(html)