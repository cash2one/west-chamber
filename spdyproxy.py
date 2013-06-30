import socket
import tlslite
import spdy.context
import spdy.frames
import select
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('', 443))
print('connected')
connection = tlslite.TLSConnection(sock)
connection.handshakeClientCert(nextProtos=['spdy/3'])
print ('TLS NPN Selected: %r' % connection.next_proto)
spdy_ctx = spdy.context.Context(spdy.context.CLIENT, version=3)

def send_frame(frame):
    spdy_ctx.put_frame(frame)
    out = spdy_ctx.outgoing()
    connection.write(out)

def read_frames():
    while True:
        answer = connection.read() # Blocking
        spdy_ctx.incoming(answer)
        frame = spdy_ctx.get_frame()
        yield frame


stream_id = spdy_ctx.next_stream_id
syn_frame = spdy.frames.SynStream(stream_id, {
    ':method' : 'GET',
    ':path'   : '/',
    ':version': 'HTTP/1.1',
    ':host'   : 'www.baidu.com',
    ':scheme' : 'http',
})
send_frame(syn_frame)
for frame in read_frames():
    if isinstance(frame, spdy.frames.SynReply):
        print(frame.headers)
    else:
        print(frame)