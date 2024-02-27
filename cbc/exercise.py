from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify,unhexlify

#Claves
key = b'ACME'*4
mac_key = b'ACME'*4

#Calculo del MAC
message = '''
Votaciones sobre empresa a contratar:
----------------------------------
public_key_paillier = 615701807411
----------------------------------
ACME-INC:
273195769081857674763628
192055108622984958392709
30762392720345566919956
81892798556741346154699
271252275147035049408427
273187728605463057361201
277504895961873757239899
68201346047604445407416
ACME-SL:
109823343090092953944017
134763215821147930810032
261150449722032877761616
283828298375388671142705
202204298264366473030119
375743045956376781795663
69837982904912717819653
35543821145848117671864
ACME-FACTORY:
153929295867379237096604
96299509908795079099099
30600080377616556113514
103326410116509808354965
352697367762765440362691
95660357923520475332996
69754211356009554787800
81917985040501402624682
'''
h = HMAC.new(mac_key, digestmod=SHA256)
h.update(message.encode('utf-8'))
mac = h.hexdigest()
message_and_mac = message+mac

#Cifrado CBC
#metodo seguro iv = get_random_bytes(AES.block_size)
iv = b'1f2A'*4
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message_and_mac.encode('utf-8'),AES.block_size))

hex_ciphertext = hexlify(ciphertext)
print('CIFRADO CBC DEL MENSAJE')
print(hex_ciphertext.decode('utf-8'))

#Descifrado CBC mediante fuerza bruta
iv_size = 4
key_size = 4
key_candidate = None
iv_candidate = None

from itertools import product
from string import ascii_letters, printable
import threading

alphabet = ascii_letters.encode()
alphanumerical = printable.encode()

# Definir una función que reciba una combinación de IV y clave, y que intente descifrar el texto cifrado
def descifrar_clave(combo):
    global key_candidate
    b_iv = b'aaaaaaaaaaaaaaaa'
    b_key = bytes(combo)*4
    cipher = AES.new(b_key, AES.MODE_CBC, b_iv)

        # Descifrar el texto cifrado usando el descifrador, eliminando el padding PKCS#7
        #Si no se utiliza la misma clave o vector iv, el padding sera incorrecto y lanzara error
    try:
        mensaje_mac = unpad(cipher.decrypt(ciphertext), AES.block_size)
        mensaje = mensaje_mac[:-64]
        b_mac = mensaje_mac[-64:]
        n_h = HMAC.new(b_key, digestmod=SHA256)
        n_h.update(mensaje)
        if n_h.hexdigest()!=b_mac.decode():
            key_candidate = b_key.decode()
            # Si se logra descifrar el texto, terminar el programa
        exit()
    except:
        pass
    

def descifrar_iv(combo):
    global iv_candidate
    b_iv = bytes(combo)*4
    b_key = key_candidate.encode()
    cipher = AES.new(b_key, AES.MODE_CBC, b_iv)

        # Descifrar el texto cifrado usando el descifrador, eliminando el padding PKCS#7
        #Si no se utiliza la misma clave o vector iv, el padding sera incorrecto y lanzara error
    try:
        mensaje_mac = unpad(cipher.decrypt(ciphertext), AES.block_size)
        mensaje = mensaje_mac[:-64]
        b_mac = mensaje_mac[-64:]
        n_h = HMAC.new(b_key, digestmod=SHA256)
        n_h.update(mensaje)
        if n_h.hexdigest()==b_mac.decode():
            iv_candidate = b_iv.decode()
            # Si se logra descifrar el texto, terminar el programa
        exit()
    except:
        pass

print("-"*30)
print("DESCIFRADO DEL MENSAJE")
combinations = product(alphabet, repeat=key_size)

# Crear un hilo por cada combinación, pasando la función y la combinación como argumentos
for combo in combinations:
    if key_candidate is not None:
        break
    t = threading.Thread(target=descifrar_clave, args=(combo,))
    t.start()
    
combinations = product(alphanumerical,repeat=iv_size)
for combo in combinations:
    if iv_candidate is not None:
        break
    t = threading.Thread(target=descifrar_iv, args=(combo,))
    t.start()
    
print(f"Obtenidos iv={iv_candidate} y key={key_candidate}")
cipher = AES.new(key_candidate.encode(), AES.MODE_CBC, iv_candidate.encode())
mensaje_mac = unpad(cipher.decrypt(ciphertext), AES.block_size)
mensaje = mensaje_mac[:-64]
b_mac = mensaje_mac[-64:]
n_h = HMAC.new(key_candidate.encode(), digestmod=SHA256)
n_h.update(mensaje)
try:
    n_h.hexverify(b_mac.decode())
    print(f"El mensaje obtenido: {mensaje.decode()}; es autentico")
except:
    print("El mensaje obtenido ha sido modificado")

