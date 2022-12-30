import random
import hashlib

from pk_transformations import uncompress
from base58_wif import b58decode
from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from typing import Optional
from rfc6979_files.rfc6979 import generate_k

from secp256k1_curve import EC

# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 256  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "english"  # Default is english
# Generate new entropy hex string
ENTROPY: str = generate_entropy(strength=STRENGTH)
# Secret passphrase for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"



def generate_bip32_key_pair(branch,step):
    
    
    hdwallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
    # Get Bitcoin HDWallet from entropy
    hdwallet.from_entropy(
        entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    )

    hdwallet.from_index(44, hardened=True)
    hdwallet.from_index(branch, hardened=True)
    hdwallet.from_index(0, hardened=True)
    hdwallet.from_index(0)
    hdwallet.from_index(step)
    

    print("Keys from path", hdwallet.path())
    print("Public Key:", hdwallet.public_key())
    print("Private Key WIF format:", hdwallet.wif(),"\n")
     

    sk_wif=hdwallet.wif()
    pk_compressed=hdwallet.public_key()
    
    pk=uncompress(pk_compressed)
    
    sk = b58decode(sk_wif)

    return sk,pk