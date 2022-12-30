from secp256k1_curve import EC

def is_on_curve(p):
    
	if p is None:
        	# None represents the point Ꝍ.
        	return True

	x, y = p

	#We check if y²-x³-a*x-b=0
	return (pow(y,2) - pow(x,3) - EC.a * x - EC.b) % EC.p == 0


def point_add(p1, p2):

	#We check if both points belongs to the curve
	assert is_on_curve(p1)
	assert is_on_curve(p2)

	if p1 is None:
		# Ꝍ + P2 = P2
		return p2
	if p2 is None:
		# P1+ Ꝍ = P1
		return p2

	x1, y1 = p1
	x2, y2 = p2

	if x1 == x2 and y1 != y2:
		# P + (-P) = Ꝍ
        	return None

    	#We check if P1==P2 in order to calculate m
	if x1 == x2:
		m = (3 * pow(x1,2) + EC.a) * pow(2 * y1, -1, EC.p)        
	else:
		m = (y1 - y2) * pow(x1 - x2, -1, EC.p)
    	       
    	#We calculate the result point P3        
	x3 = (pow(m,2) - x1 - x2) % EC.p
	y3 = (m*(x1-x3)-y1) % EC.p
	p3 = (x3,y3)

    	#We check if the point belongs to the curve
	assert is_on_curve(p3), "Point does not belong to the curve"

	return p3


def scalar_multiply(k, p):

    	#We check if the point belongs to the curve
    	assert is_on_curve(p), "Point does not belong to the curve"

    	if k % EC.n == 0 or p is None:
    		# None represents the point Ꝍ.
        	return None

    	if k <0:
        	# k*P = -k*(-P)
        	return scalar_multiply(-k, point_neg(p))

    	q = None
    	aux_p = p

    	#We go through all the bits of k
    	while k:
    		#We check if the bit is 1
        	if k & 1:
            		# We add
            		q = point_add(q, aux_p)

      		#We double
        	aux_p = point_add(aux_p, aux_p)

		#We make a shift right to get the next bit
        	k >>= 1

    	#We check if the point belongs to the curve
    	assert is_on_curve(q)

    	return q
    
def point_neg(p):
    #Returns -P
    
    #We check if the point belongs to the curve
    assert is_on_curve(p)

    if p is None:
        # -Ꝍ= Ꝍ
        return None

    x, y = p
    
    result = (x, -y % EC.p)
    
    #We check if the point belongs to the curve
    assert is_on_curve(result)

    return result
