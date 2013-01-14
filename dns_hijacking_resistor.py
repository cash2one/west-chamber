import sys
import subprocess

# source http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
WRONG_ANSWERS = {
    '4.36.66.178',
    '8.7.198.45',
    '37.61.54.158',
    '46.82.174.68',
    '59.24.3.173',
    '64.33.88.161',
    '64.33.99.47',
    '64.66.163.251',
    '65.104.202.252',
    '65.160.219.113',
    '66.45.252.237',
    '72.14.205.99',
    '72.14.205.104',
    '78.16.49.15',
    '93.46.8.89',
    '128.121.126.139',
    '159.106.121.75',
    '169.132.13.103',
    '192.67.198.6',
    '202.106.1.2',
    '202.181.7.85',
    '203.161.230.171',
    '207.12.88.98',
    '208.56.31.43',
    '209.36.73.33',
    '209.145.54.50',
    '209.220.30.174',
    '211.94.66.147',
    '213.169.251.35',
    '216.221.188.182',
    '216.234.179.13'
}

rules = ['-p udp --sport 53 -m u32 --u32 "4 & 0x1FFF = 0 && 0 >> 22 & 0x3C @ 8 & 0x8000 = 0x8000 && 0 >> 22 & 0x3C @ 14 = 0" -j DROP']
for wrong_answer in WRONG_ANSWERS:
    hex_ip = ' '.join(['%02x' % int(s) for s in wrong_answer.split('.')])
    rules.append('-p udp --sport 53 -m string --algo bm --hex-string "|%s|" --from 60 --to 180  -j DROP' % hex_ip)

try:
    for rule in rules:
        print(rule)
        subprocess.call('iptables -I INPUT %s' % rule, shell=True)
    print('running..')
    sys.stdin.readline()
except KeyboardInterrupt:
    print('bye')
finally:
    for rule in reversed(rules):
        subprocess.call('iptables -D INPUT %s' % rule, shell=True)