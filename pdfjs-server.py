#!/usr/bin/env python3

# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from http.server import HTTPServer, SimpleHTTPRequestHandler, test

WEBROOT = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pdfjs')

def get_csp():
    with open(os.path.join(WEBROOT, '_headers')) as f:
      CSP_PREFIX = 'Content-Security-Policy: '
      lines = [l.strip() for l in f.readlines()]
      lines = [l for l in lines if l.startswith(CSP_PREFIX)]
      if len(lines) != 1:
        raise ValueError("Expected exactly one CSP line in _headers. Found: " + str(lines))
      return lines[0].removeprefix(CSP_PREFIX)

class CSPRequestHandler(SimpleHTTPRequestHandler):
  def __init__(self, request, client_address, server):
    SimpleHTTPRequestHandler.__init__(self, request, client_address, server, directory=WEBROOT)

  def end_headers (self):
    self.send_header('Content-Security-Policy', get_csp())
    SimpleHTTPRequestHandler.end_headers(self)

print('serving from ' + WEBROOT)
print('go to http://127.0.0.1:8123/web/viewer.html')
test(CSPRequestHandler, HTTPServer, port=8123, bind='127.0.0.1')
