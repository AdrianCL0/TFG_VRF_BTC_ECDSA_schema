# Analysis and Applications of VRFs
In this project we will implement in Python a VRF protocol using EC based on Bitcoin’s ECDSA (Elliptic Curve Digital Signature Algorithm) digital signature scheme 
in order to solve the problem of Anti-Exfil.

## Reference Implementations

The purpose of this implementation is for solving the Anti-Exfil problem of Bitcoin ECDSA signatures in a most efficient way. We measure this efficiency in the number 
of messages and not in size, since in this type of transaction the important thing is the number of communications.

## VRF Protocol
Our implementation consists of an ECDSA Signature together with a VRF for the generation of random numbers and their corresponding proofs. In addition, for key generation we will use BIP32, since from an entropy we can generate a master key that will allow us to derive public and private keys in different paths. One path will be for the signatures and another for the VRF. Finally, those values that should be randomly generated within the VRF will be generated using the RFC6979 standard.
