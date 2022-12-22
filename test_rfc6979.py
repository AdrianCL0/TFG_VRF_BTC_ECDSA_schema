import random
import hashlib

from rfc6979_files.rfc6979 import generate_k
from secp256k1_curve import EC


priv=0xba644470e4e5de06d20b57e54a73c84f31e76c2ecfeb723e83ec0e509d5737fe
data=b'Data for nonce generation'

nonce=generate_k(EC.n, priv, hashlib.sha256, data)

nonce2=generate_k(EC.n, priv, hashlib.sha256, data)

assert(nonce==nonce2), "Non deterministic nonce generation"