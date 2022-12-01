import collections

EllipticCurve = collections.namedtuple('BTC_EllipticCurve', 'name p a b g n h')

EC = EllipticCurve(

    name='secp256k1',
    
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    
    # Curve coefficients.
    a=0,
    b=7,
    
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
       
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    
    # Cofactor.
    h=1,
)

