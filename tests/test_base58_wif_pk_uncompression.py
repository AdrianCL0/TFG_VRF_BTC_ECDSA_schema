from pk_transformations import uncompress
from base58_wif import b58decode
from ecdsa_methods import scalar_multiply
from secp256k1_curve import EC


################################### TEST 1 ###################################

print("Test 1:\n")


x1=0xba644470e4e5de06d20b57e54a73c84f31e76c2ecfeb723e83ec0e509d5737fe
y1_compressed="028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474"


xwif="L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY"

sk1 = b58decode(xwif)

print("WIF-SK:L3U2ofZ1V7t1Xe9aheQhWiQ33VzA47ym7Z7G9JTzp7skg1BAgtdY\n")
print("Hex Verified SK: ",hex(x1))
print("Hex SK Decoded: ",hex(sk1),"\n")


pk1=uncompress(y1_compressed)
y1=scalar_multiply(x1,EC.g)

print("PK compressed: 028e2ccb1410f18d3db4ba8d9084692295e8c60bd348a211aefff2890d829d7474")
print("Uncompressed Verified PK:",pk1)
print("PK generated with SK*G:", scalar_multiply(x1,EC.g),"\n")

assert(sk1==x1),"_______________TEST 1 WIF TRANSFORMATION FAILED_______________\n"
assert(pk1==y1),"_______________TEST 1 PK UNCOMPRESSION FAILED_______________\n"

print ("________TEST 1 WIF TRANSFORMATION AND PK UNCOMPRESSION PASSED________\n")


################################### TEST 2 ################################### 
print("Test 2:\n")


x2=0xf5d45e03b3bac386baafa23f8f3ddd2849849b528591f8e059e06ea9c535de01
y2_compressed="033045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9"


xwif2="L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2"

sk2 = b58decode(xwif2)
  
print("WIF-SK:L5Ta6WqMXd7DRY8Q6jD9PwDtTeYaNR4Ch9arGHRqmYmB2PLGSkp2")
print("Hex Verified SK: ",hex(x2))
print("Hex SK Decoded: ",hex(sk2),"\n")


pk2=uncompress(y2_compressed)
y2=scalar_multiply(x2,EC.g)

print("PK compressed: 033045230f2388735c9b76fbc01a59d1c5b581699c3faac0d2bb0ce317bcfe7cc9")
print("Uncompressed Verified PK:",pk2)
print("PK generated with SK*G:", scalar_multiply(x2,EC.g),"\n")

assert(sk2==x2),"_______________TEST 2 WIF TRANSFORMATION FAILED_______________\n"
assert(pk2==y2),"_______________TEST 2 PK UNCOMPRESSION FAILED_______________\n"

print ("________TEST 2 WIF TRANSFORMATION AND PK UNCOMPRESSION PASSED________\n")


################################### TEST 2 ###################################

print("Test 3:\n")
print("WIF-SK:Kzi4WCKVf88L99tEnEAKQa4Wb3ffosFi8NhRGSRaVwSwfYVB6oWt")


x3=0x6818bfdad40b8fe45654c517194a40dd7985d5e66204f75fcafe4ed0ee7af2a8
y3_compressed="0329305dd685b5165865a8e04d081b5246d8a83eed2252031fc1bc3d0ccc8dc693"

xwif3="Kzi4WCKVf88L99tEnEAKQa4Wb3ffosFi8NhRGSRaVwSwfYVB6oWt"

sk3 = b58decode(xwif3)

print("Hex Verified SK: ",hex(x3))
print("Hex SK Decoded: ",hex(sk3),"\n")

pk3=uncompress(y3_compressed)
y3=scalar_multiply(x3,EC.g)

print("PK compressed: 0329305dd685b5165865a8e04d081b5246d8a83eed2252031fc1bc3d0ccc8dc693")
print("Uncompressed Verified PK:",pk3)
print("PK generated with SK*G:", scalar_multiply(x3,EC.g),"\n")


assert(sk3==x3),"_______________TEST 3 WIF TRANSFORMATION FAILED_______________\n"
assert(pk3==y3),"_______________TEST 3 PK UNCOMPRESSION FAILED_______________\n"

print ("________TEST 3 WIF TRANSFORMATION AND PK UNCOMPRESSION PASSED________\n")