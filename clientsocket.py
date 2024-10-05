import socket
import os
import hmac
import hashlib
import secrets

HOST = "127.0.0.1"  # Dirección IP del servidor
PORT = 3030  # Puerto utilizado por el servidor
CLAVE_SECRETA = b'supersecretkey'  # Debe ser la misma clave que en el servidor
NONCE_FILE = "nonce.txt" 

# Función para generar un Nonce aleatorio
def generar_nonce():
    nonce = secrets.token_hex(16)
    while(nonce in leer_nonces_usados()):
        nonce = secrets.token_hex(16)
    return nonce

# Leer los nonces usados desde el archivo
def leer_nonces_usados():
    if os.path.exists(NONCE_FILE):
        with open(NONCE_FILE, 'r') as file:
            nonces = file.read().splitlines()
            return set(nonces)
    return set()

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
    origen = input("Ingrese el IBAN del origen: ")  
    destino = input("Ingrese el IBAN del destino: ")  
    cantidad = input("Ingrese la cantidad en euros: ")   
    mensaje = f"Enviar {cantidad} euros desde {origen} a {destino}"
    return f"{mensaje}:{origen}:{destino}:{cantidad}"

# Crear el socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Obtener y enviar datos del usuario
    datos = obtener_datos()
    
    # Enviar usuario, contraseña al servidor
    s.sendall(f"{datos}".encode('utf-8'))
    
    # Recibir la respuesta del servidor
    respuesta = s.recv(1024).decode('utf-8')
    print(f"Respuesta del servidor: {respuesta}")

    if "Enviado con exito" in respuesta:
        # Enviar el mensaje de transferencia
        # Mensaje:
        mensaje_transferencia = enviar_transferencia()  
        # Nonce:
        nonce = "NONCEYAUSADO"
        #nonce = generar_nonce() 
        # Mac:
        mac_cliente = crear_mac(mensaje_transferencia.split(":")[0], nonce)   
        s.sendall(f"{mensaje_transferencia}:{mac_cliente}:{nonce}".encode('utf-8'))
        print("Transferencia: ",mensaje_transferencia.split(":")[0])
        # Recibir la aceptacion del servidor de la transferencia
        aceptacion_transferencia = s.recv(1024).decode('utf-8')
        print(f"Respuesta del servidor sobre la transferencia: {aceptacion_transferencia}")
        # Correcion de errores en el iban o en la cantidad:
        while(aceptacion_transferencia == "Error: Iban invalido." or aceptacion_transferencia == "Error: Cantidad invalida."):
            mensaje_transferencia = enviar_transferencia()
            s.sendall(f"{mensaje_transferencia}:{mac_cliente}:{nonce}".encode('utf-8'))
            print("Transferencia: ",mensaje_transferencia.split(":")[0])
            aceptacion_transferencia = s.recv(1024).decode('utf-8')
            print(f"Respuesta del servidor sobre la transferencia: {aceptacion_transferencia}")
        # Transferencia Validada:
        
            
        
  