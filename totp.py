#!/usr/bin/python

"""
    HOTP: An HMAC-Based One-Time Password
        and
    TOTP: Time-Based One-Time Password
        algorithms
"""

import time, hmac
from base64 import b32decode

def hotp(K, C, n_digits=6, algo='sha1'):
    """HOTP: An HMAC-Based One-Time Password Algorithm [RFC 4226]
       K        - shared secret bytes
       C        - 8 byte counter value
       n_digits - is one of 6,7 or 8
       algo     - is one of sha1, sha256 or sha512
    """
    hash = hmac.new(K, C, algo).digest()
    offset = hash[-1] & 0x0f
    truncated = hash[offset:offset+4]
    integer = int.from_bytes(truncated, 'big')
    integer &= 0x7fffffff
    otp = integer % 10**n_digits
    result = str(otp).zfill(n_digits)
    return result

def totp(K, period=30, n_digits=6, algo='sha1'):
    """TOTP: Time-Based One-Time Password Algorithm [RFC 6238]
       K        - shared secret bytes
       period   - time step size, in seconds
       n_digits - is one of 6,7 or 8
       algo     - is one of sha1, sha256 or sha512
    """
    time_step = int(time.time()) // period
    C = time_step.to_bytes(8, 'big')
    return hotp(K, C, n_digits, algo)

def totp_from_base32_key(b32key, period=30, n_digits=6, algo='sha1'):
    """Returns TOTP from a Base32-encoded key
       b32key   - bytes or string of the key
       period   - time step size, in seconds
       n_digits - is one of 6,7 or 8
       algo     - is one of sha1, sha256 or sha512
    """
    K = b32decode(b32key)
    return totp(K, period, n_digits, algo)

if __name__ == '__main__':
    import sys, argparse
    par = argparse.ArgumentParser(
            description="""
                Returns Time-Based One-Time Password (TOTP)
                from a Base32-encoded secret
            """
          )
    add = par.add_argument
    add('secret', type=str)
    algos = ['sha1', 'sha256', 'sha512']
    add('-a', '--algo', type=str, default='sha1', choices=algos)
    add('-p', '--period', type=int, default=30)
    add('-d', '--digits', type=int, default=6)
    args = par.parse_args()
    try:
        if args.period not in range(30, 86400+1):
            raise Exception("--period (-p) not in 30..86400 range")
        if args.digits not in range(6, 8+1):
            raise Exception("--digits (-d) not in 6..8 range")
        params = (args.secret, args.period, args.digits, args.algo)
        totp_val = totp_from_base32_key(*params)
        print(totp_val)
    except Exception as e:
        print('Error:', e)
        exit(1)
