import random
import hashlib

from rfc6979_files.rfc6979 import generate_k
from bip32_keys import generate_bip32_key_pair
from vrf_methods import get_proof_and_value, verify_proof_and_value, h2
from ec_operations import scalar_multiply, point_add, is_on_curve

from secp256k1_curve import EC

BRANCH_ECDSA=10
STEP_ECDSA = 0


def get_key_pair():
	#We generate a random number mod n that will be the SK
	sk = random.randint(0, EC.n-1)
	#We derivate the PK as SK*G
	pk = scalar_multiply(sk,EC.g)
	return [sk,pk]

def get_bip32_ecdsa_key_pair():
    
    global STEP_ECDSA
    
    sk,pk=generate_bip32_key_pair(BRANCH_ECDSA, STEP_ECDSA)
    
    STEP_ECDSA=STEP_ECDSA+1
    
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

def get_rfc6979_signature(m,sk,alpha):

	#We calculate the message hash and we transformed to an int
    h=int(hashlib.sha256(m.encode()).hexdigest(),16)
    
    #We generathe the hash of alpha and transform it into bytes
    data=hashlib.sha256(str(alpha).encode()).digest()
	
	#We generate a deterministic random number with RFC6979 standard
    k_e = generate_k(EC.n, sk, hashlib.sha256, data)
    
    print (f"Deterministic RFC6979 nonce:\n{k_e}\n")
	
	#We calculate the value of the point R
    r_point = scalar_multiply(k_e,EC.g)

	#We define the value r as the x-coordinate of the R point
    r = r_point[0] % EC.n
	
	#We calculate the inverse mod n of k_e
    k_e_inv = pow(k_e,-1,EC.n)

	#We calculate the value s as s=ke^-1*(h+r*d)
    s = (k_e_inv*(h+r*sk)) % EC.n

    return r,s

def get_vrf_signature(m,alpha,d,x,PK):
    
    ko=int(hashlib.sha256((str(d)+str(alpha)).encode()).hexdigest(),16)
    
    Ro=scalar_multiply(ko, EC.g)
    
    pi,t= get_proof_and_value(alpha, x, PK)
    
    k= t+ko % EC.n
    
    #We calculate the value of the point R
    R=point_add(Ro,scalar_multiply(t, EC.g))
    
	#We define the value r as the x-coordinate of the R point
    r = R[0] % EC.n

	#We calculate the message hash and we transformed to an int
    e=int(hashlib.sha256(m.encode()).hexdigest(),16)
    
    #print (f"Deterministic RFC6979 nonce:\n{k_e}\n")
		
	#We calculate the inverse mod n of k_e
    k_inv = pow(k,-1,EC.n)

	#We calculate the value s as s=ke^-1*(h+r*d)
    s = (k_inv*(e+d*r)) % EC.n

    return Ro,R,s,pi

def verify_vrf_signature(Ro,R,s,m,alpha,pi,PK,B):
    
    assert(verify_proof_and_value(alpha, pi, PK))
    
    t=h2((scalar_multiply(EC.h, pi[0]))) 
    
    #We calculate the value of the point R
    R=point_add(Ro,scalar_multiply(t, EC.g))
    
	#We define the value r as the x-coordinate of the R point
    r = R[0] % EC.n

	#We calculate the message hash and we transformed to an int
    e=int(hashlib.sha256(m.encode()).hexdigest(),16)
	
	#We calculate the inverse of s mod n
    w = pow(s,-1,EC.n)
	
	#We calculate the values of u1 and u2
    u1=(e*w) % EC.n
    u2=(r*w) % EC.n
	
	#We calculate the point P as the result of u1*G+u2*PK
    Z = point_add(scalar_multiply(u1,EC.g), scalar_multiply(u2,B))

	#We define the r' as the x-coordinate of the point P
    r_estimated = Z[0] % EC.n
		
    return r_estimated==r
	
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


