import socket
import ssl
import spdylay
import M2Crypto

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('198.52.103.140', 443))
def callback(*args, **kwargs):
    print('!!!')
    return 0
try:
    ssl_ctx = M2Crypto.SSL.Context(protocol='sslv3')
    ssl_ctx.set_next_protocol_callback(callback)
    sock = M2Crypto.SSL.Connection(ssl_ctx, sock)
    sock.setup_ssl()
    sock.connect_ssl()
    sock.setblocking(False)
    session = spdylay.Session(spdylay.CLIENT, spdylay.PROTO_SPDY3)
    session.submit_request(0,
                           [(':method', 'GET'),
                            (':scheme', 'https'),
                            (':path', '/'),
                            (':version', 'HTTP/1.1'),
                            (':host', 'baidu.com:80'),
                            ('accept', '*/*'),
                            ('user-agent', 'python-spdylay')])
    session.send()
finally:
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()