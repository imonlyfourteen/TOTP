#!/usr/bin/python

import sys
from base64 import b32decode
from time import time
import hmac

# https://datatracker.ietf.org/doc/html/rfc4226

def DT(s):
    o = s[-1] & 0xf
    p = bytes([s[o] & 0x7f, *s[o+1:o+4]])
    return p

def StToNum(b):
    return int.from_bytes(b, 'big')
    
def TOTP(b32secret, n_digits=6, period=30):
    K = b32decode(b32secret)
    t = int(time()) // period
    C = t.to_bytes(8, 'big')
    HS = hmac.new(K, C, 'sha1').digest()
    Sbits = DT(HS)
    Snum = StToNum(Sbits)
    D = Snum % 10**n_digits
    return str(D).zfill(n_digits)

if len(sys.argv) > 1:
    print(TOTP(sys.argv[1].encode()))
else:
    print(f"Usage: {sys.argv[0]} <secret>")
    exit(1)
