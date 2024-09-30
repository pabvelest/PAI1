import socket
import hmac
import hashlib
import secrets

HOST = "127.0.0.1"  # Dirección IP del servidor
PORT = 3030  # Puerto utilizado por el servidor
CLAVE_SECRETA = b'supersecretkey'  # Debe ser la misma clave que en el servidor

# Función para generar un Nonce aleatorio
def generar_nonce():
    return secrets.token_hex(16)

# Función para crear HMAC con SHA-512
def crear_mac(mensaje, nonce):
    mensaje_con_nonce = mensaje + nonce
    return hmac.new(CLAVE_SECRETA, mensaje_con_nonce.encode('utf-8'), hashlib.sha512).hexdigest()

# Función para solicitar datos de usuario
def obtener_datos():
    usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")
    return f"{usuario}:{contraseña}"

# Función para enviar transferencia
def enviar_transferencia():
    mensaje = input("Ingrese el mensaje de transferencia: ")    
    return f"{mensaje}"

# Crear el socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Obtener y enviar datos del usuario
    datos = obtener_datos()
    nonce = generar_nonce()
    mac_cliente = crear_mac(datos, nonce)

    # Mostrar por pantalla el MAC, el Nonce y los datos
    print(f"Datos: {datos}")
    print(f"Nonce generado: {nonce}")
    print(f"MAC generado (HMAC): {mac_cliente}")
    
    # Enviar usuario, contraseña, nonce y mac al servidor
    s.sendall(f"{datos}:{nonce}:{mac_cliente}".encode('utf-8'))
    
    # Recibir la respuesta del servidor
    respuesta = s.recv(1024).decode('utf-8')
    print(f"Respuesta del servidor: {respuesta}")

    if "Enviado con exito" in respuesta:
        # Enviar el mensaje de transferencia
        mensaje_transferencia = enviar_transferencia()
        s.sendall(mensaje_transferencia.encode('utf-8'))
        
        # Recibir respuesta sobre la transferencia
        respuesta_transferencia = s.recv(1024).decode('utf-8')
        print(f"Respuesta del servidor sobre transferencia: {respuesta_transferencia}")
