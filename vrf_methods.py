import hashlib

from ecdsa.numbertheory import square_root_mod_prime
from rfc6979_files.rfc6979 import generate_k
from ec_operations import scalar_multiply, point_add
from secp256k1_curve import EC
from bip32_keys import generate_bip32_key_pair

BRANCH_VRF=17
STEP_VRF = 0

def get_bip32_vrf_key_pair():
    
    global STEP_VRF
    
    sk,pk=generate_bip32_key_pair(BRANCH_VRF, STEP_VRF)
    
    STEP_VRF=STEP_VRF+1
    
    return [sk,pk]


def _hash_to_curve(alpha,pk):
    condition=False
    i=0
    while condition == False:
        x=int(hashlib.sha256((str(alpha)+str(pk)+str(i)).encode()).hexdigest(),16)
        square_y=(pow(x,3,EC.p)+EC.a*x+EC.b) % EC.p
        try:
            y = square_root_mod_prime(square_y, EC.p)
            condition=True
        except:
            condition=False
            i=i+1
    return [x,y]

def _h3(g,h,alpha,beta,gamma,delta):
    
    g_string=','.join(map(str,g))
    
    h_string=','.join(map(str,h))
    
    alpha_string=','.join(map(str,alpha))
    
    beta_string=','.join(map(str,beta))
    
    gamma_string=','.join(map(str,gamma))
    
    delta_string=','.join(map(str,delta))
    
    joined_string=g_string+h_string+alpha_string+beta_string+gamma_string+delta_string
    
    return int(hashlib.sha256((joined_string).encode()).hexdigest(),16)

def h2(p):
    
    p_string=','.join(map(str,p))
    
    return int(hashlib.sha256((p_string).encode()).hexdigest(),16)
    

def get_proof_and_value(alpha,x,PK):
    
    H=_hash_to_curve(alpha, PK)
    
    gamma_proof=scalar_multiply(x, H)
    
    #We generathe the hash of alpha and transform it into bytes
    data=hashlib.sha256(str(alpha).encode()).digest()
    
    #We generate a deterministic random number with RFC6979 standard
    k_e = generate_k(EC.n, x, hashlib.sha256, data)
    
    Alpha=scalar_multiply(x, EC.g)
    
    Beta=scalar_multiply(x, H)
    
    Gamma=scalar_multiply(k_e, EC.g)
    
    Delta=scalar_multiply(k_e, H)
    
    c=_h3(EC.g,H,Alpha,Beta,Gamma,Delta)
    
    s_prima=(k_e-c*x) % EC.n
    
    proof=[gamma_proof,c,s_prima]

    value= h2((scalar_multiply(EC.h, gamma_proof)))   
    
    return proof,value
    

def verify_proof_and_value(alpha,proof,PK):
     
    gamma_proof=proof[0]
    
    c=proof[1]
    
    s_prima=proof[2]
    
    U1=scalar_multiply(c, PK)
    
    U2=scalar_multiply(s_prima, EC.g)
    
    U=point_add(U1, U2)
    
    H=_hash_to_curve(alpha, PK)
    
    V1=scalar_multiply(c, gamma_proof)
    
    V2=scalar_multiply(s_prima, H)
    
    V=point_add(V1, V2)
    
    assert(c==_h3(EC.g,H,PK,gamma_proof,U,V))
    
    return True
    