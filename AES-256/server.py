import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Nombre del archivo que almacena la clave
KEY_FILE = 'key.bin'


def load_key():
    # Cargar la clave desde un archivo
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
    return key

def handle_client(client_socket, key):
    cipher = AES.new(key, AES.MODE_CBC)
    while True:
        try:
            # Recibir datos del cliente
            data = client_socket.recv(1024)
            if not data:
                break  # Si no se reciben datos, cerrar la conexión

            # Extraer el IV y el texto cifrado de los datos recibidos
            iv = data[:16]  # El IV tiene 16 bytes en CBC
            cipher_text = data[16:]

            # Crear un cifrador AES con la clave y el IV recibido
            decipher = AES.new(key, AES.MODE_CBC, iv)
            text = unpad(decipher.decrypt(cipher_text), AES.block_size).decode()
            print(f"Cliente: {text}")

            # Pedir al usuario que introduzca una respuesta
            response = input("Tu respuesta: ")

            # Crear un nuevo IV para la respuesta
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Cifrar la respuesta
            cipher_text = cipher.encrypt(pad(response.encode(), AES.block_size))

            # Enviar el IV y el texto cifrado al cliente
            message = iv + cipher_text
            client_socket.sendall(message)

        except ConnectionResetError:
            print("Conexión restablecida por el cliente.")
            break
        except Exception as e:
            print(f"Error: {e}")
            break
    
    client_socket.close()

def start_server(host='0.0.0.0', port=12345):
    # Generar y guardar una clave (se debería hacer una vez y compartir por un canal seguro)
    key = load_key()

    # Crear un socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Enlazar el socket a la dirección IP y el puerto
    server_socket.bind((host, port))
    
    # Escuchar conexiones entrantes
    server_socket.listen(1)
    print(f"Esperando conexión en {host}:{port}...")
    
    while True:
        try:
            # Aceptar una conexión
            client_socket, client_address = server_socket.accept()
            print(f"Conectado a {client_address}")

            

            # Crear un hilo para manejar la comunicación con el cliente
            client_handler = threading.Thread(target=handle_client, args=(client_socket, key))
            client_handler.start()
        except Exception as e:
            print(f"Error en el servidor: {e}")

if __name__ == "__main__":
    start_server()
