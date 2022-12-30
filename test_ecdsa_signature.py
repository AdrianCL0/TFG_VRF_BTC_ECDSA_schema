import sys
import configparser as config

from ecdsa_methods import get_key_pair,get_signature,verify_signature
from secp256k1_curve import EC

#We get the parameters of the transaction to sign and define the m as the tx id
config_obj = config.ConfigParser()
config_obj.read("./config.ini")
tx_config = config_obj["tx"]
m = tx_config["id"]

#We check if the execution has parameters, if it does we define m as the parameter
if len(sys.argv) > 1:
  m=(sys.argv[1])
  
#We check if the curve discriminant is correct
def check_curve_parameters():
	return -16*(4*pow(EC.a,3)+27*pow(EC.b,2))!=0 

assert check_curve_parameters(), "Curve Discriminant not valid"

#We get ALice's key pair
[sk,pk]=get_key_pair()

print (f"Alice's public key: {pk}\n")

#We sign the message m with Alice's private key
r,s=get_signature(m,sk)

print (f"Message: {m}\n\nSignature S=(r,s):\n[r={r},\ns={s}]\n")

#We verify the signature S=(r,s) of the message m with Alice's public key
assert(verify_signature(r,s,m,pk)),"______________Signature could not be verified______________\n"
print ("_______________Signature has been verified correctly_______________\n")



