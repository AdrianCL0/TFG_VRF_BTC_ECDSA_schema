m="Missatge de Prova"
pk="028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474"
from secp256k1_curve import EC
from math import sqrt
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa_methods import scalar_multiply, is_on_curve

import hashlib



def hash_to_curve(alpha,pk):
    condition=False
    i=0
    while condition == False:
        x=int(hashlib.sha256((alpha+str(pk)+str(i)).encode()).hexdigest(),16)
        square_y=(pow(x,3,EC.p)+EC.a*x+EC.b) % EC.p
        try:
            y = square_root_mod_prime(square_y, EC.p)
            condition=True
        except:
            condition=False
            i=i+1
    return [x,y]




p=hash_to_curve(m, pk) 

assert(is_on_curve(p)) 

  