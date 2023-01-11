import hashlib

from ecdsa.numbertheory import square_root_mod_prime
from rfc6979_files.rfc6979 import generate_k
from ec_operations import scalar_multiply, point_add, is_on_curve
from secp256k1_curve import EC
from bip32_keys import generate_bip32_key_pair

BRANCH_VRF=17
STEP_VRF = 0


def get_bip32_vrf_key_pair():
    
    global STEP_VRF
    
    #We generate a key pair for the VRF schema
    sk,pk=generate_bip32_key_pair(BRANCH_VRF, STEP_VRF)
    
    #We increment the step value for the next key
    STEP_VRF=STEP_VRF+1
    
    return [sk,pk]


def _hash_to_curve(alpha,pk):
    
    condition=False
    i=0
    
    #We iterate until we get a x value that has an y value in the curve
    while condition == False:
        
        #We make the hash of the alpha, pk and a number and we define it as x
        x=int(hashlib.sha256((str(alpha)+str(pk)+str(i)).encode()).hexdigest(),16)
        
        #We calculate y^2 as x^3+ax+b mod p
        square_y=(pow(x,3,EC.p)+EC.a*x+EC.b) % EC.p
        
        #We try to get sqrt(y)
        try:
            #If we can get the y value we finish the loop
            y = square_root_mod_prime(square_y, EC.p)
            condition=True
        except:
            #If we can not get the y value we increment the nummber
            condition=False
            i=i+1
            
    return [x,y]

def _h3(g,h,alpha,beta,gamma,delta):
    
    #We transform all the points to strings
    g_string=','.join(map(str,g))   
    h_string=','.join(map(str,h))   
    alpha_string=','.join(map(str,alpha))   
    beta_string=','.join(map(str,beta))    
    gamma_string=','.join(map(str,gamma))   
    delta_string=','.join(map(str,delta))
    
    #We join all the strings    
    joined_string=g_string+h_string+alpha_string+beta_string+gamma_string+delta_string
    
    #We make the hash of the string of the six points and transformed to int
    return int(hashlib.sha256((joined_string).encode()).hexdigest(),16)

def h2(p):
    
    #We transform the point to string
    p_string=','.join(map(str,p))
    
    #We return the hash of the string point in int format
    return int(hashlib.sha256((p_string).encode()).hexdigest(),16)
    

def get_proof_and_value(alpha,x,PK):
    
    #We calculte H as H1(alpha,pk) where H is a point
    H=_hash_to_curve(alpha, PK)
    
    assert(is_on_curve(H)), "Point H does not belong to curve"
    
    #We calculate γ as x*H
    gamma_proof=scalar_multiply(x, H)
    
    #We generathe the hash of alpha and we transform it into bytes
    data=hashlib.sha256(str(alpha).encode()).digest()
    
    #We generate a deterministic random number with RFC6979 standard
    k_e = generate_k(EC.n, x, hashlib.sha256, data)
    
    #We get the points that we need for H3()
    Alpha=scalar_multiply(x, EC.g)    
    Beta=scalar_multiply(x, H)    
    Gamma=scalar_multiply(k_e, EC.g)   
    Delta=scalar_multiply(k_e, H)
    
    #We calculate c as H3(G,H,x*G,x*H,ke*G,ke*H)
    c=_h3(EC.g,H,Alpha,Beta,Gamma,Delta)
    
    #We calculte s' as ke-c*x mod n
    s_prima=(k_e-c*x) % EC.n
    
    #We define the proof π = (γ,c,s’)
    pi=[gamma_proof,c,s_prima]

    #We get the value as H2(h*γ)
    value= h2((scalar_multiply(EC.h, gamma_proof)))   
    
    return pi,value
    

def verify_proof_and_value(alpha,pi,PK):
    
    #We get γ from π
    gamma_proof=pi[0]
    
    #We get c from π
    c=pi[1]
    
    #We get s' from π
    s_prima=pi[2]
    
    #We calculate U=U1+U2 where U1 is c*PK and U2 is s'*G
    U1=scalar_multiply(c, PK)
    U2=scalar_multiply(s_prima, EC.g)  
    U=point_add(U1, U2)
    
    #We calculte H as H1(alpha,pk) where H is a point
    H=_hash_to_curve(alpha, PK)
    
    #We calculate V=V1+V2 where V1 is c*γ and U2 is s'*H
    V1=scalar_multiply(c, gamma_proof)
    V2=scalar_multiply(s_prima, H)
    V=point_add(V1, V2)
    
    #We calculate c_prima as H3(G,H,PK,γ,U,V)
    c_prima=_h3(EC.g,H,PK,gamma_proof,U,V)
    
    return c==c_prima
    