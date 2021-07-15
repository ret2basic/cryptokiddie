def cbc_cca(cc: bytes, mm: bytes):
	"""
	Description:

	If we have an decryption oracle, we can easily recover the IV. To learn more:
	https://www.ctfnote.com/crypto/block-ciphers/aes/cbc-cca
	
	Args:

	- cc: a byte string containing two identical blocks as ciphertext
	- mm: a byte string containing the output from the decryption oracle

	Output:

	- iv: the initialization vector recovered from the CBC CCA attack

	Caution:

	The ciphertext cc must contain two identical blocks. Two 16-byte blocks containing
	only null bytes are recommended.
	"""
	assert len(cc) == 32, "The first argument must be a 32-byte byte string."
	assert cc[:16] == cc[16:], "The first argument must have the same block 1 and block 2."
	
	p0 = mm[:16]
	p1 = mm[16:]

	iv = xor(xor(p0, p1), cc[:16])

	return iv