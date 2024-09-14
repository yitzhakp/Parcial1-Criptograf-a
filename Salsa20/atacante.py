from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

key = b'\x40\x41\x2a\xa1\x3a\xae\xdb\x7a\x16\xd7\xe2\x55\x82\x55\x68\x82\x63\x63\x6d\xe1\x2c\xda\x75\x80\xdf\x5e\xd9\x05\xf6\xee\xb8\x6d'
print(key)


data = b'\x75\xc4\xec\xc0\xb4\xb5\xf2\xa5\x67\x1f\x62\x73'

nonceS = data[:8]
cipherText = data[8:]
#Decifra el mensaje con la llave y el nonce correspondiente
decipher = Salsa20.new(key=key, nonce=nonceS)
text = decipher.decrypt(cipherText).decode()

print(text)
