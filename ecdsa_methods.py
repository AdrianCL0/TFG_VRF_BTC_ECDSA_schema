import random
import hashlib

from pk_transformations import compress,uncompress
from base58_wif import b58decode
from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from typing import Optional

from secp256k1_curve import EC


# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 256  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "english"  # Default is english
# Generate new entropy hex string
ENTROPY: str = generate_entropy(strength=STRENGTH)
# Secret passphrase for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"
position = 0




def get_key_pair():
	#We generate a random number mod n that will be the SK
	sk = random.randint(0, EC.n-1)
	#We derivate the PK as SK*G
	pk = scalar_multiply(sk,EC.g)
	return [sk,pk]

def get_bip32_key_pair():
    
    global position
    
    hdwallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
    # Get Bitcoin HDWallet from entropy
    hdwallet.from_entropy(
        entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    )

    hdwallet.from_index(44, hardened=True)
    hdwallet.from_index(0, hardened=True)
    hdwallet.from_index(0, hardened=True)
    hdwallet.from_index(0)
    hdwallet.from_index(position)
    
    print(f"Keys from path 44/0/0/0/{position}")
    print("Public Key:", hdwallet.public_key())
    print("Private Key WIF format:", hdwallet.wif(),"\n")
    
    position=position+1
    

    sk_wif=hdwallet.wif()
    pk_compressed=hdwallet.public_key()
    
    pk=uncompress(pk_compressed)
    
    b = b58decode(sk_wif)
    PK0 = b.hex()
    PK0=PK0[2:]
    sk= int(PK0[:64],16)


    
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

	return r,s
	
def verify_signature(r,s,m,pk):

	#We calculate the message hash and we transformed to an int
	h=int(hashlib.sha256(m.encode()).hexdigest(),16)
	
	#We calculate the inverse of s mod n
	w = pow(s,-1,EC.n)
	
	#We calculate the values of u1 and u2
	u1=(h*w) % EC.n
	u2=(r*w) % EC.n
	
	#We calculate the point P as the result of u1*G+u2*PK
	P = point_add(scalar_multiply(u1,EC.g), scalar_multiply(u2,pk))

	#We define the r' as the x-coordinate of the point P
	r_estimated = P[0] % EC.n
		
	return r_estimated==r


def is_on_curve(p):
    
	if p is None:
        	# None represents the point Ꝍ.
        	return True

	x, y = p

	#We check if y²-x³-a*x-b=0
	return (pow(y,2) - pow(x,3) - EC.a * x - EC.b) % EC.p == 0


def point_add(p1, p2):

	#We check if both points belongs to the curve
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

    	#We check if the point belongs to the curve
	assert is_on_curve(p3), "Point does not belong to the curve"

	return p3


def scalar_multiply(k, p):

    	#We check if the point belongs to the curve
    	assert is_on_curve(p), "Point does not belong to the curve"

    	if k % EC.n == 0 or p is None:
    		# None represents the point Ꝍ.
        	return None

    	if k <0:
        	# k*P = -k*(-P)
        	return scalar_multiply(-k, point_neg(p))

    	q = None
    	aux_p = p

    	#We go through all the bits of k
    	while k:
    		#We check if the bit is 1
        	if k & 1:
            		# We add
            		q = point_add(q, aux_p)

      		#We double
        	aux_p = point_add(aux_p, aux_p)

		#We make a shift right to get the next bit
        	k >>= 1

    	#We check if the point belongs to the curve
    	assert is_on_curve(q)

    	return q
