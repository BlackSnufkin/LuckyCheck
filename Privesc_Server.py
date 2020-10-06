import http.server
import socketserver
import os
import Updater

Updater.main()

PORT = 8200
Handler = http.server.SimpleHTTPRequestHandler


class HTTPRequestHandler(Handler):
    """Extend SimpleHTTPRequestHandler to handle PUT requests"""

    def do_PUT(self):
        """Save a file following a HTTP PUT request"""
        filename = os.path.basename(self.path)

        # Don't overwrite files
        if os.path.exists(filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '[!] "%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, '[#] Created')
        self.end_headers()
        reply_body = '[#] Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))


try:
    with socketserver.TCPServer(("", PORT), HTTPRequestHandler) as httpd:
        print("[#] The Server Port is:", PORT)
        httpd.serve_forever()
except KeyboardInterrupt as error:
    print(error)
    print('[!] Shouting Down The Server ...')

# Upload via: curl -X PUT --upload-file test.txt http://localhost:8200
