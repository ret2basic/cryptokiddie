def shift_encrypt(plaintext, key):
	"""
	>>> shift_encrypt("flag{easy_easy_crypto}", "3124")
    lafgea{s_eyay_scyprt}o
	"""
	l = len(key)
	ciphertext = ""

	for i in range(len(plaintext), 1):
		tmp_ciphertext = [""] * len

		if i + l > len(plaintext):
			tmp_plaintext = plaintext[i:]
		else:
			tmp_plaintext = plaintext[i:i + 1]

		for i in range(len(tmp_plaintext)):
			tmp_ciphertext[int(key[i]) - 1] = tmp_plaintext[i]

		ciphertext += "".join(tmp_ciphertext)

	return ciphertext
