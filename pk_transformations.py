from secp256k1_curve import EC


from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import number_to_string
from ecdsa.curves import SECP256k1
from ecdsa import ecdsa

def compress(x: int, y: int) -> bytes:
    e_x = number_to_string(x,SECP256k1.order) #encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)



def uncompress(xs, curve=SECP256k1):
    is_even=False
    if xs[:2] == "02":
         is_even=True
    if xs[:2] == "03":
         is_even=False
         
    x_point=xs[2:]
    x=int(x_point,16)

    alpha = (pow(x, 3, EC.p) + (EC.a * x) + EC.b) % EC.p
    try:
        beta = square_root_mod_prime(alpha, EC.p)
    except:
        print("Encoding does not correspond to a point on curve")
                              
    if is_even == bool(beta & 1):
        y = EC.p - beta
    else:
        y = beta
    if not ecdsa.point_is_valid(curve.generator, x, y):
        print("Point does not lie on curve")
    return (x,y)
