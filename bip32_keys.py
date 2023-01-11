from pk_transformations import uncompress
from base58_wif import b58decode
from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from typing import Optional


# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 256  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "english"  # Default is english
# Generate new entropy hex string
ENTROPY: str = generate_entropy(strength=STRENGTH)
# Secret passphrase for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"



def generate_bip32_key_pair(branch,step):
    
    #We generate a BIP32 key pair from a branch and a step
    
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
     
    
    #We get the wif private key and the compressed public key
    sk_wif=hdwallet.wif()
    pk_compressed=hdwallet.public_key()
    
    #We uncompress the public key
    pk=uncompress(pk_compressed)
    
    #We transform the WIF private key from base58 to int
    sk = b58decode(sk_wif)

    return sk,pk