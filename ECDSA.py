import random
import hashlib

from secp256k1 import EC


def get_key_pair():
	sk = random.randint(0, EC.n-1)
	pk = scalar_multiply(sk,EC.g)
	return [sk,pk]

def get_signature(m,sk):

	#We calculate the message hash and we transformed to an int
	h=int(hashlib.sha256(m.encode()).hexdigest(),16)
	
	#We generate a random number that latter would be generated through a VRF
	k_e = random.randint(0, EC.n-1)
	
	#We calculate the value of the point R
	r_point = scalar_multiply(k_e,EC.g)

	#We define the value r as the x-coordinate of the R point
	r = r_point[0] % EC.n
	
	#We calculate the inverse mod n of k_e
	k_e_inv = pow(k_e,-1,EC.n)

	#We calculate the value s as s=ke^-1*(h+r*d)
	s = (k_e_inv*(h+r*sk)) % EC.n

	return s,r
	
def verify_signature(s,r,m,pk):

	h=int(hashlib.sha256(m.encode()).hexdigest(),16)
	
	inv_s = pow(s,-1,EC.n)
	c = inv_s
	u1=(h*c) % EC.n
	u2=(r*c) % EC.n
	P = point_add(scalar_multiply(u1,EC.g), scalar_multiply(u2,pk))

	res = P[0] % EC.n
		
	return res==r


def is_on_curve(p):
    
    if p is None:
        # None represents the point Ꝍ.
        return True

    x, y = p

    #We check if y²-x³-a*x-b=0
    return (pow(y,2) - pow(x,3) - EC.a * x - EC.b) % EC.p == 0


def point_add(p1, p2):

    assert is_on_curve(p1)
    assert is_on_curve(p2)

    if p1 is None:
        # Ꝍ + P2 = P2
        return p2
    if p2 is None:
        # P1+ Ꝍ = P1
        return p2

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        # P + (-P) = Ꝍ
        return None

    #We check if P1==P2 in order to calculate m
    if x1 == x2:
     	m = (3 * pow(x1,2) + EC.a) * pow(2 * y1, -1, EC.p)        
    else:
    	m = (y1 - y2) * pow(x1 - x2, -1, EC.p)
    	       
    #We calculate the result point P3        
    x3 = (pow(m,2) - x1 - x2) % EC.p
    y3 = (m*(x1-x3)-y1) % EC.p
    p3 = (x3,y3)

    assert is_on_curve(p3), "Point does not belong to the curve"

    return p3


def scalar_multiply(k, p):

    
    assert is_on_curve(p), "Point does not belong to the curve"

    if k % EC.n == 0 or p is None:
    	# None represents the point Ꝍ.
        return None

    if k <0:
        # k*P = -k*(-P)
        return scalar_multiply(-k, point_neg(p))

    q = None
    aux_p = p

    while k:
        if k & 1:
            # Add.
            q = point_add(q, aux_p)

        # Double.
        aux_p = point_add(aux_p, aux_p)

        k >>= 1

    assert is_on_curve(q)

    return q

