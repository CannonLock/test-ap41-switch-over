"""Stand-in for https://osg-htc.org: serves the federation discovery document as a static file over HTTPS.

Runs in the Origin image (Python 3.9). Usage: python3 serve.py <web root> <cert> <key>
"""

import functools
import http.server
import ssl
import sys

root, cert, key = sys.argv[1:4]


class Handler(http.server.SimpleHTTPRequestHandler):
    def guess_type(self, path):
        return "application/json"


server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), functools.partial(Handler, directory=root))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
