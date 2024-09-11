import socket
import threading

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

key = None
def receive_messages(client_socket):
    global key
    k = True
    #Escuchar periodicamente el canal
    while True:
        try:
            data = client_socket.recv(1024)
            #Si no llegan datos, rompe el ciclo
            if not data:
                break

            #El primer mensaje contiene la llave
            if(k):
                key = data
                k = False
            #Los otros mensajes ya están cifrados
            else:
                #Divide los datos en nonce y mensaje
                nonceS = data[:8]
                cipherText = data[8:]
                #Decifra el mensaje con la llave y el nonce correspondiente
                decipher = Salsa20.new(key=key, nonce=nonceS)
                text = decipher.decrypt(cipherText).decode()
                print(f"Servidor: {text}")
        except ConnectionResetError:
            break

    client_socket.close()

def start_client(server_ip, server_port):
    global key
    # Crear un socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
    # Conectar al servidor
    client_socket.connect((server_ip, server_port))
   
    # Crear un hilo para recibir mensajes del servidor
    receiver_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receiver_thread.start()
   
    # Enviar mensajes al servidor
    while True:
        message = input("Tu mensaje: ")
        #Genera un nonce para cada mensaje
        nonce = get_random_bytes(8)
        cipher = Salsa20.new(key=key, nonce=nonce)
        #Cifra el mensaje
        cipherText = cipher.encrypt(message.encode())
        #Combina el nonce y el mensaje
        mess = nonce + cipherText
        client_socket.sendall(mess)

if __name__ == "__main__":
    server_ip = '192.168.1.2'  # Cambia esto a la IP del servidor
    server_port = 12345
    start_client(server_ip, server_port)
