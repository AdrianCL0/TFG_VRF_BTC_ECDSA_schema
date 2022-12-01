from pk_transformations import compress,uncompress
from base58_wif import b58decode
from ecdsa_methods import scalar_multiply
from secp256k1_curve import EC

print("Test 1\n")
print("Key 1: \nPK: 028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474 \nWIF-SK:L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY")


x1=0xba644470e4e5de06d20b57e54a73c84f31e76c2ecfeb723e83ec0e509d5737fe
y1="028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474"

xwif="L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY"



b = b58decode(xwif)
PK0 = b.hex()  

print("Hex SK: ",PK0,"\n")
print("Hex Verified SK: ",hex(x1),"\n")

pk=uncompress(y1)

print("Uncompressed PK:",pk,"\n")
print("PK generated with SK*G:", scalar_multiply(x1,EC.g),"\n")


print("Test 2\n")
print("Key 2: \nPK: 033045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9	 \nWIF-SK:L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2")


x2=0xf5d45e03b3bac386baafa23f8f3ddd2849849b528591f8e059e06ea9c535de01
y2="033045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9"

xwif2="L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2"

b = b58decode(xwif2)
PK0 = b.hex()  

print("Hex SK: ",PK0,"\n")
print("Hex Verified SK: ",hex(x2),"\n")

pk2=uncompress(y2)

print("Uncompressed PK:",pk2,"\n")
print("PK generated with SK*G:", scalar_multiply(x2,EC.g),"\n")



print("Test 3\n")
print("Key 3: \nPK: 0329305dd685b5165865a8e04d081b5246d8a83eed2252031fc1bc3d0ccc8dc693	 \nWIF-SK:Kzi4WCKVf88L99tEnEAKQa4Wb3ffosFi8NhRGSRaVwSwfYVB6oWt")


x3=0x6818bfdad40b8fe45654c517194a40dd7985d5e66204f75fcafe4ed0ee7af2a8
y3="0329305dd685b5165865a8e04d081b5246d8a83eed2252031fc1bc3d0ccc8dc693"

xwif3="Kzi4WCKVf88L99tEnEAKQa4Wb3ffosFi8NhRGSRaVwSwfYVB6oWt"

b = b58decode(xwif3)
PK0 = b.hex()  

print("Hex SK: ",PK0,"\n")
print("Hex Verified SK: ",hex(x3),"\n")

pk3=uncompress(y3)

print("Uncompressed PK:",pk3,"\n")
print("PK generated with SK*G:", scalar_multiply(x3,EC.g),"\n")