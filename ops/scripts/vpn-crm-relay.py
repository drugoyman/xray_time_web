#!/usr/bin/env python3
"""Fixed TCP/UDP relay. Changes only owned chains/jumps; never flushes Docker.

Run apply/remove/status as root on the CRM server. TLS/WG keys stay on the VPN.
SNAT forces replies through CRM. Reapplying reconciles only this project's rules.
"""
import fcntl
import json
import pathlib
import subprocess
import sys

PUBLIC = '217.18.60.102'
BACKEND = '89.19.209.17'
INTERFACE = 'eth0'
MAPPINGS = [('tcp', 14443, 443), ('udp', 51820, 51820), ('udp', 22067, 22067)]
COMMENT = 'xray_time_web CRM relay'
CHAINS = [('nat', 'VPNCRM_DNAT'), ('nat', 'VPNCRM_SNAT'),
          ('filter', 'VPNCRM_FWD')]
JUMPS = [
    ('nat', 'PREROUTING', ['-i', INTERFACE, '-d', PUBLIC, '-j', 'VPNCRM_DNAT']),
    ('nat', 'POSTROUTING', ['-o', INTERFACE, '-d', BACKEND, '-j', 'VPNCRM_SNAT']),
    ('filter', 'DOCKER-USER', ['-j', 'VPNCRM_FWD']),
]


def ipt(table, *args, check=True):
    result = subprocess.run(['iptables', '-w', '10', '-t', table, *args],
                            text=True, capture_output=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or 'iptables failed')
    return result


def append(table, chain, args):
    ipt(table, '-A', chain, *args, '-m', 'comment', '--comment', COMMENT)


def detach():
    # Delete only exact project jumps; preserve all unrelated rules and policies.
    for table, chain, args in JUMPS:
        while ipt(table, '-C', chain, *args, check=False).returncode == 0:
            ipt(table, '-D', chain, *args)


def remove():
    detach()
    for table, chain in CHAINS:
        if ipt(table, '-S', chain, check=False).returncode == 0:
            ipt(table, '-F', chain)
            ipt(table, '-X', chain)


def apply():
    if pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
        raise RuntimeError('IPv4 forwarding must already be enabled')
    ipt('filter', '-S', 'DOCKER-USER')
    # Keep existing owned jumps while rebuilding our private chains. A reapply
    # can briefly interrupt relay traffic, but cannot redirect CRM web ports.
    for table, chain in CHAINS:
        if ipt(table, '-S', chain, check=False).returncode:
            ipt(table, '-N', chain)
        ipt(table, '-F', chain)
    try:
        for protocol, external, internal in MAPPINGS:
            original = ['-m', 'conntrack', '--ctproto', protocol,
                        '--ctorigdst', PUBLIC, '--ctorigdstport', str(external)]
            append('nat', 'VPNCRM_DNAT',
                   ['-p', protocol, '--dport', str(external), '-j', 'DNAT',
                    '--to-destination', f'{BACKEND}:{internal}'])
            append('nat', 'VPNCRM_SNAT',
                   ['-p', protocol, '--dport', str(internal), *original,
                    '-j', 'SNAT', '--to-source', PUBLIC])
            append('filter', 'VPNCRM_FWD',
                   ['-i', INTERFACE, '-o', INTERFACE, '-p', protocol,
                    '-d', BACKEND, '--dport', str(internal), *original,
                    '--ctdir', 'ORIGINAL', '--ctstate', 'NEW,ESTABLISHED',
                    '-j', 'ACCEPT'])
            append('filter', 'VPNCRM_FWD',
                   ['-i', INTERFACE, '-o', INTERFACE, '-p', protocol,
                    '-s', BACKEND, '--sport', str(internal), *original,
                    '--ctdir', 'REPLY', '--ctstate', 'ESTABLISHED',
                    '-j', 'ACCEPT'])
        for table, chain, args in JUMPS:
            if ipt(table, '-C', chain, *args, check=False).returncode:
                ipt(table, '-I', chain, '1', *args)
    except BaseException:
        remove()
        raise


def status():
    print(json.dumps({'public': PUBLIC, 'backend': BACKEND,
                      'mappings': MAPPINGS}))
    for table, chain in CHAINS:
        print(ipt(table, '-nvL', chain, check=False).stdout.strip())


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('apply', 'remove', 'status'):
        raise SystemExit('Usage: vpn-crm-relay.py apply|remove|status')
    with open('/run/lock/vpn-crm-relay.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        globals()[sys.argv[1]]()
