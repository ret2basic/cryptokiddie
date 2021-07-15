def cbc_cca(decrypted: bytes):
	"""
	Description:

	If we have an decryption oracle, we can easily recover the IV. To learn more:
	https://www.ctfnote.com/crypto/block-ciphers/aes/cbc-cca
	
	Args:

	- decrypted: a byte string containing the output we get from the decryption oracle

	Output:

	- iv: the initialization vector recovered from the CBC CCA attack

	Caution:

	The ciphertext cc must contain two identical blocks. Two 16-byte blocks containing
	only null bytes are recommended.
	"""
	p0 = decrypted[:16]
	p1 = decrypted[16:]

	iv = xor(xor(p0, p1), b"\x00" * 16)

	return iv