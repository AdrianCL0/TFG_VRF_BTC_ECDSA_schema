import sys
from hashlib import sha256
from collections import deque
DEFAULT_CHARSET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
import configparser as config
import base58

from ecdsa2 import get_key_pair,get_signature,verify_signature,scalar_multiply
from secp256k1 import EC


from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import string_to_number, number_to_string
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
from ecdsa import ecdsa

def _b58decode_int(val, base, charset):
        output = 0
        for char in val:
            output = output * base + charset.index(char)
        return output


def b58decode(val, charset=DEFAULT_CHARSET):
    if isinstance(val, str):
        val = val.encode()

    if isinstance(charset, str):
        charset = charset.encode()

    base = len(charset)

    if not base == 58:
        raise ValueError('charset base must be 58, not %s' % base)

    pad_len = len(val)
    val = val.lstrip(bytes([charset[0]]))
    pad_len -= len(val)

    acc = _b58decode_int(val, base, charset)

    result = deque()
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.appendleft(mod)

    prefix = b'\0' * pad_len
    return prefix + bytes(result)
    
    
def compress(x: int, y: int) -> bytes:
    e_x = number_to_string(x,SECP256k1.order) #encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)



def uncompress(x, is_even,curve=SECP256k1) -> Point:
    order = curve.order
    p = curve.curve.p()
    alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
    try:
        beta = square_root_mod_prime(alpha, p)
    except SquareRootError as e:
        raise MalformedPoint(
            "Encoding does not correspond to a point on curve", e
        )                                 
    if is_even == bool(beta & 1):
        y = p - beta
    else:
        y = beta
    if not ecdsa.point_is_valid(curve.generator, x, y):
        raise MalformedPoint("Point does not lie on curve")
    return Point(curve.curve, x, y, order)






print("Test 1\n")
print("Key 1: \nPK: 028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474 \nWIF-SK:L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY")


x1=0xba644470e4e5de06d20b57e54a73c84f31e76c2ecfeb723e83ec0e509d5737fe
y1=0x8e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474

xwif="L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY"



b = b58decode(xwif)
PK0 = b.hex()  

print("Hex SK: ",PK0,"\n")
print("Hex Verified SK: ",hex(x1),"\n")

pk=uncompress(y1,1)

print("Uncompressed PK:",pk,"\n")
print("PK generated with SK*G:", scalar_multiply(x1,EC.g),"\n")


print("Test 2\n")
print("Key 1: \nPK: 033045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9	 \nWIF-SK:L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2")


x2=0xf5d45e03b3bac386baafa23f8f3ddd2849849b528591f8e059e06ea9c535de01
y2=0x3045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9

xwif2="L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2"



b = b58decode(xwif2)
PK0 = b.hex()  

print("Hex SK: ",PK0,"\n")
print("Hex Verified SK: ",hex(x2),"\n")

pk2=uncompress(y2,0)

print("Uncompressed PK:",pk2,"\n")
print("PK generated with SK*G:", scalar_multiply(x2,EC.g),"\n")

