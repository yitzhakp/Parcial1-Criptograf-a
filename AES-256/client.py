import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def read_key_from_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def receive_messages(client_socket, key):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break  # Si no se reciben datos, cerrar la conexión

            # Extraer el IV y el texto cifrado de los datos recibidos
            iv = data[:16]  # El IV tiene 16 bytes en CBC
            cipher_text = data[16:]

            # Crear un cifrador AES con la clave y el IV recibido
            decipher = AES.new(key, AES.MODE_CBC, iv)
            text = unpad(decipher.decrypt(cipher_text), AES.block_size).decode()
            print(f"Servidor: {text}")
        except (ConnectionResetError, ValueError) as e:
            print(f"Error: {e}")
            break

    client_socket.close()

def start_client(server_ip, server_port, key):
    # Crear un socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
    # Conectar al servidor
    client_socket.connect((server_ip, server_port))
   
    # Crear un hilo para recibir mensajes del servidor
    receiver_thread = threading.Thread(target=receive_messages, args=(client_socket, key))
    receiver_thread.start()
   
    # Enviar mensajes al servidor
    while True:
        message = input("Tu mensaje: ")
        # Generar un IV para cada mensaje
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Asegurarse de que el mensaje sea múltiplo de 16 bytes (padding)
        padded_message = pad(message.encode(), AES.block_size)
        cipher_text = cipher.encrypt(padded_message)
        # Combinar el IV y el mensaje cifrado
        mess = iv + cipher_text
        client_socket.sendall(mess)

if __name__ == "__main__":
    server_ip = '192.168.1.14'  # Cambia esto a la IP del servidor
    server_port = 12345
    
    # Leer la llave desde el archivo
    key = read_key_from_file('key.bin')

    # Verificar que la llave tiene el tamaño correcto
    if len(key) != 32:
        raise ValueError("La llave debe tener 256 bits (32 bytes).")

    start_client(server_ip, server_port, key)
