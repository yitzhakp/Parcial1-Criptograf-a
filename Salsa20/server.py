import socket
import threading

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
print(f"Llave generada: {key}")

def handle_client(client_socket):
    while True:
        try:
            # Recibir datos del cliente
            data = client_socket.recv(1024)
            if not data:
                break
            nonceU = data[:8]
            cipherTextU = data[8:]
            decipher = Salsa20.new(key=key, nonce=nonceU)
            text = decipher.decrypt(cipherTextU).decode()
            print(f"Cliente: {text}")

            # Enviar una respuesta (texto plano)
            response = input("Tu respuesta: ")

            nonce = get_random_bytes(8)
            cipher = Salsa20.new(key=key, nonce=nonce)

            cipherText = cipher.encrypt(response.encode())
            mess = nonce + cipherText
            client_socket.sendall(mess)

        except ConnectionResetError:
            break
    
    client_socket.close()

def start_server(host='0.0.0.0', port=12345):
    # Crear un socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Enlazar el socket a una dirección IP y un puerto
    server_socket.bind((host, port))
    
    # Escuchar conexiones entrantes
    server_socket.listen(1)
    print(f"Esperando conexión en {host}:{port}...")
    
    # Aceptar una conexión
    client_socket, client_address = server_socket.accept()
    client_socket.sendall(key)
    print(f"Conectado a {client_address}")
    
    # Crear un hilo para manejar la comunicación con el cliente
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

if __name__ == "__main__":
    start_server()
