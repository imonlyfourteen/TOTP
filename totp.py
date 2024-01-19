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
    import sys, os, platform, argparse

    parser = argparse.ArgumentParser(
        description="""
            Returns Time-Based One-Time Password (TOTP)
            from a Base32-encoded secret
        """
    )
    
    plat = platform.system()
    user_dir = {
        'Linux'  : '~/.config/totp/', 
        'Windows': '~/AppData/Local/totp/'
    }.get(plat)
    
    if user_dir:
        default_path = os.path.expanduser(user_dir)
        default_file = default_path + '.totp_secrets'
    else:
        default_file = None

    algos = ['sha1', 'sha256', 'sha512']
    
    add = parser.add_argument
    grpx = parser.add_mutually_exclusive_group()
    x_add = grpx.add_argument
   
    add('secret', nargs='?', type=str)
    x_add('-s', '--set', type=str)
    x_add('-r', '--remove', type=str)
    x_add('-g', '--get', type=str)
    x_add('-l', '--list', action='store_true')
    add('-a', '--algo', type=str, default='sha1', choices=algos)
    add('-p', '--period', type=int, default=30)
    add('-d', '--digits', type=int, default=6)
    add('-f', '--file', type=str, default=default_file)
    args = parser.parse_args()
    
    def sel(s):
        return {k : args.__dict__[k] for k in s}
    
    def params2cmd():
        s = {'algo', 'period', 'digits'}
        return ' '.join(f'--{k} {v}' for k,v in sel(s).items())
    
    def isfileop():
        s= {'set', 'remove', 'get', 'list'}
        return any(sel(s).values())
        
    def touch(f):
        os.close(os.open(f, os.O_CREAT | os.O_RDWR, mode=0o600))
    
    def line_format(service, secret, cmdlineargs):
        return f'{service} {secret} {cmdlineargs}\n'
    
    def parse_file(file):
        d = {}
        for line in open(file):
            k,s,a = line.strip().split(maxsplit=2)
            d[k] = [s,a]
        return d
    
    def wirte_records(file, r):
        f = open(file, 'w')
        for k,(s,a) in r.items():
            line = line_format(k, s, a)
            f.write(line)
        f.close()
        
    def info(m):
        print("Info:", m, file=sys.stderr)
        
    def print_totp(secret, a):
        params = (secret, a.period, a.digits, a.algo)
        totp_val = totp_from_base32_key(*params)
        print(totp_val)
                
    try:
        if args.period not in range(30, 86400+1):
            raise Exception("--period (-p) not in 30..86400 range")
        if args.digits not in range(6, 8+1):
            raise Exception("--digits (-d) not in 6..8 range")
        
        if isfileop():
            if not args.file:
                raise Exception("No file specified")
            if os.path.isdir(args.file):
                raise Exception(f"'{args.file}' is a directory")
            if not os.path.exists(args.file):
                if not args.set:
                    raise Exception(f"File '{args.file}' does not exist, "
                                     "use '--set' argument to add a service")
                d,f = os.path.split(args.file)
                os.makedirs(d, exist_ok=True)
                touch(args.file)
                info(f"File '{args.file}' has been created")
            
            records = parse_file(args.file)
                
            if args.set:
                if args.set in records:
                    raise Exception(f"Service '{args.set}' already exists")
                if not args.secret:
                    raise Exception(f"A secret must be specified")
                # try to decode a secret:
                b32decode(args.secret)
                line = line_format(args.set, args.secret, params2cmd())
                f = open(args.file, 'a')
                f.write(line)
                f.close()
                info(f"Added '{args.set}' to file '{args.file}'")
            elif args.remove:
                if not args.remove in records:
                    raise Exception(f"No such service '{args.remove}'")
                records.pop(args.remove)
                wirte_records(args.file, records)
                info(f"Service '{args.remove}' has been removed")
            elif args.get:
                if not args.get in records:
                    raise Exception(f"No such service '{args.get}'")
                secret, a = records[args.get]
                args_svc = parser.parse_args(a.split())
                print_totp(secret, args_svc)
            else: # --list
                if records:
                    print(f"List of available services from '{args.file}':\n")
                    print(f"{'Service':18} : {'Secret':^18} : Arguments")
                    for k,(s,a) in sorted(records.items()):
                        print(f'{k:18} : {s:^18} : {a}')
                else:
                    print(f"The file '{args.file}' is empty")
                    
        else: # not a file op
            print_totp(args.secret, args)
            
    except Exception as e:
        print('Error:', e)
        exit(1)
