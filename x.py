import os, hmac, hashlib, binascii, secrets, string

# Generate an 8-char ASCII salt similar to common frameworks
_ALPHABET = string.ascii_letters + string.digits
def random_salt(n: int = 8) -> str:
    return ''.join(secrets.choice(_ALPHABET) for _ in range(n))

def make_hash(password: str, iterations: int = 150000, salt: str | None = None) -> str:
    if salt is None:
        salt = random_salt(8)          # don't reuse salts
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                             salt.encode('utf-8'), iterations)
    dk_hex = binascii.hexlify(dk).decode()
    return f"pbkdf2:sha256:{iterations}${salt}${dk_hex}"

def check_hash(stored: str, candidate: str) -> bool:
    # expected: pbkdf2:sha256:<iters>$<salt>$<hex>
    scheme, algo, iters, tail = stored.split(':', 3)
    if scheme != 'pbkdf2' or algo != 'sha256':
        raise ValueError("Unsupported hash format")
    salt, hex_dk = tail.split('$', 1)
    dk = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'),
                             salt.encode('utf-8'), int(iters))
    return hmac.compare_digest(binascii.hexlify(dk).decode(), hex_dk)

# EXAMPLE (authorized reset on your own system):
new_hash = make_hash("Rahma123")
print(new_hash)                              # store this string in your DB

