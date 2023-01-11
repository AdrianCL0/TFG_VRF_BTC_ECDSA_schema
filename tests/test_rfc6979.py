import hashlib

from rfc6979_files.rfc6979 import generate_k
from secp256k1_curve import EC

#We define a private key to which generate de nonce
priv=0xba644470e4e5de06d20b57e54a73c84f31e76c2ecfeb723e83ec0e509d5737fe

#We define the message
data=b'Data for nonce generation'

#We generate the nonce
nonce=generate_k(EC.n, priv, hashlib.sha256, data)

#We generate again the nonce with the same parameters
nonce2=generate_k(EC.n, priv, hashlib.sha256, data)

#We check its determinisitc behaviour
assert(nonce==nonce2), "_______________TEST RFC6979 NONCE GENERATION FAILED_______________\n"

print ("_______________TEST RFC6979 NONCE GENERATION PASSED_______________\n")