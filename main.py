import sys
import random

from ecdsa_methods import get_vrf_signature,verify_vrf_signature,get_bip32_ecdsa_key_pair
from secp256k1_curve import EC
from vrf_methods import get_bip32_vrf_key_pair 

def main():

    #We read the file that contains the transactions to sign
    file = open('transactions.txt', 'r')
    txs = file.readlines()
    
    #We check if the execution has parameters, if it does we define m as the parameter
    if len(sys.argv) > 1:
      m=(sys.argv[1])
      
    #We check if the curve discriminant is correct
    def check_curve_parameters():
    	return -16*(4*pow(EC.a,3)+27*pow(EC.b,2))!=0 
    
    assert check_curve_parameters(), "Curve Discriminant not valid"
    
    number_of_tx = int(input("How many transactions do you want to sign?: "))
    
    #We iterate n time to sign with n bip32 different keys and verify its vrf signatures
    for i in range(number_of_tx):
        
        #We get the next transaction id to sign and we define it as m
        m=txs[i]
        
        print ("ECDSA:")
        #We get ALice's ECDSA key pair with BIP32
        [d,B]=get_bip32_ecdsa_key_pair()
        
        print ("VRF:")
        #We get ALice's VRF key pair with BIP32
        [x,PK]=get_bip32_vrf_key_pair()
        
        print (f"Alice's public ECDSA key: {B}\n")
        print (f"Alice's public VRF key: {PK}\n")
        
        #We generate a random value that will be used in the signature
        alpha=random.randint(0, EC.n-1)
        
        #We sign the message m with Alice's private key using VRF
        Ro,R,s,pi=get_vrf_signature(m,alpha,d,x,PK)
        
        print (f"Message: {m}\n\nSignature: S=(R,Ro,s):\n[R={R},\nRo={Ro},\ns={s}]\n")
        print (f"VRF: π = (γ,c,s’):\n[γ={pi[0]},\nc={pi[1]},\ns'={pi[2]}]\n")
        
        #We verify the signature S=(R,Ro,s) and the proof VRF π = (γ,c,s’) of the message m with Alice's public key
        assert(verify_vrf_signature(Ro, R, s, m, alpha, pi, PK, B)),"______________Signature could not be verified______________\n"
        print ("_______________Signature has been verified correctly_______________\n")
  
    print (f"__________ALL {number_of_tx} TRANSACTIONS HAVE BEEN SIGNED AND VERIFIED__________\n")
    
if __name__ == "__main__":
    main()