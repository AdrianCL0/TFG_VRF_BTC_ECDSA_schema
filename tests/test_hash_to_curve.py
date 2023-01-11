import hashlib

from secp256k1_curve import EC
from ecdsa.numbertheory import square_root_mod_prime
from ec_operations import is_on_curve


#We define the message to hash
m="Test Message"

#We define the public key with which make the hash
pk="028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474"

#We define a function that hashes a value to a EC point
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

#We get the point
p=hash_to_curve(m, pk) 

#We check if the point belongs to the curve
assert(is_on_curve(p)), "_______________TEST HASH TO CURVE FAILED_______________\n"

print ("_______________TEST HASH TO CURVE PASSED_______________\n")


  