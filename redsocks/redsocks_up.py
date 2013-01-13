import signal
import subprocess
import os

REDSOCKS_CONF_PATH = os.path.join(os.path.dirname(__file__), 'redsocks.conf')

def clean_up(*args):
    subprocess.call('iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner stowaway -j REDSOCKS', shell=True)
    subprocess.call('iptables -t nat --flush REDSOCKS', shell=True)
    subprocess.call('iptables -t nat -X REDSOCKS', shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -t nat -N REDSOCKS', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN', shell=True)
    subprocess.call('iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345', shell=True)
    subprocess.call('iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner stowaway -j REDSOCKS', shell=True)
    print('running..')
    subprocess.call('redsocks {}'.format(REDSOCKS_CONF_PATH), shell=True)
except KeyboardInterrupt:
    print('bye')
finally:
    clean_up()