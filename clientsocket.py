import socket

HOST = "127.0.0.1"  # Dirección IP del servidor
PORT = 3030  # Puerto utilizado por el servidor

# Función para solicitar datos de usuario
def obtener_datos():
    usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")
    return f"{usuario}:{contraseña}"

def enviar_transferencia():
    mensaje = input("Ingrese el mensaje de transferencia: ")    
    return f"{mensaje}"

# Crear el socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Obtener y enviar datos del usuario
    datos = obtener_datos()
    s.sendall(datos.encode('utf-8'))
    
    # Recibir la respuesta del servidor
    data = s.recv(1024)


print(f"Recibido {data.decode('utf-8')}")

