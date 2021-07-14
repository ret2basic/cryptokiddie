def cbc_bit_flipping(cookie: string, message: string, position: list, target: list) -> bytes:
	"""
	Description:

	CBC Bit Flipping attack is usually used when you are given a cookie that contains
	"admin=False" and you want to flip it to "admin=True".

	Args:

	- cookie: as hex string
	- message: a plaintext string, for example, "admin=False"
	- position: an integer list containing indices in the message, for example, [16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
	- target: a list of desired outcome after flipping, for example, ["a", "d", "m", "i", "n", "=", "T", "r", "u", "e"]
	
	Output:

	- result: the flipped cookie as byte string

	Caution:

	The arg "position" must contain indices greater than 16 since we must skip the first block
	and modify the content starting from the second block.
	"""
	l = len(position)
	result = bytes.fromhex(cookie)

	for i in range(l):
		change = position[i] - 16 # Change the ciphertext from the previous block
		flipped = xor(message.encode()[position[i]], target[i], bytes.fromhex(cookie)[change]) # Bit flipping
		result = result[:change] + flipped + result[change+1:]

	return result