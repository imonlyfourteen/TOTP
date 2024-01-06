# TOTP & HOTP Python module

TOTP: Time-Based One-Time Password Algorithm [RFC 6238]  
HOTP: An HMAC-Based One-Time Password Algorithm [RFC 4226]

```python
Help on module totp:

NAME
    totp

DESCRIPTION
    HOTP: An HMAC-Based One-Time Password
        and
    TOTP: Time-Based One-Time Password
        algorithms

FUNCTIONS
    hotp(K, C, n_digits=6, algo='sha1')
        HOTP: An HMAC-Based One-Time Password Algorithm [RFC 4226]
        K        - shared secret bytes
        C        - 8 byte counter value
        n_digits - is one of 6,7 or 8
        algo     - is one of sha1, sha256 or sha512
    
    totp(K, period=30, n_digits=6, algo='sha1')
        TOTP: Time-Based One-Time Password Algorithm [RFC 6238]
        K        - shared secret bytes
        period   - time step size, in seconds
        n_digits - is one of 6,7 or 8
        algo     - is one of sha1, sha256 or sha512
    
    totp_from_base32_key(b32key, period=30, n_digits=6, algo='sha1')
        Returns TOTP from a Base32-encoded key
        b32key   - bytes or string of the key
        period   - time step size, in seconds
        n_digits - is one of 6,7 or 8
        algo     - is one of sha1, sha256 or sha512
```

Can be used as a command-line TOTP generator:

```bash
$ python -m totp --help
usage: totp.py [-h] [-a {sha1,sha256,sha512}] [-p PERIOD] [-d DIGITS] secret

Returns Time-Based One-Time Password (TOTP) from a Base32-encoded secret

positional arguments:
  secret

options:
  -h, --help            show this help message and exit
  -a {sha1,sha256,sha512}, --algo {sha1,sha256,sha512}
  -p PERIOD, --period PERIOD
  -d DIGITS, --digits DIGITS
```

```bash
$ python -m totp JBSWY3DPEHPK3PXP
054285
```
