import socket
import mysql.connector
import hashlib
import hmac
import os
import secrets
from mysql.connector import Error

HOST = "127.0.0.1"
PORT = 3030
CLAVE_SECRETA = b'supersecretkey'  # Clave secreta para HMAC (debería almacenarse de forma segura)
NONCE_FILE = "nonce.txt"

# Función para conectar con la base de datos MySQL
def conectar_base_datos():
    try:
        conexion = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="users"
        )
        if conexion.is_connected():
            return conexion
    except Error as e:
        print(f"Error al conectar a MySQL: {e}")
        return None

# Función para verificar si el usuario ya existe en la base de datos
def usuario_existe(conexion, usuario):
    try:
        cursor = conexion.cursor()
        query = "SELECT 1 FROM usuarios WHERE nombre_usuario = %s"
        cursor.execute(query, (usuario,))
        resultado = cursor.fetchone()
        return resultado is not None
    except Error as e:
        print(f"Error al verificar si el usuario existe: {e}")
        return False

# Función para generar el hash SHA-3 de una contraseña
def hashear_contrasena_sha3(contrasena):
    contrasena_bytes = contrasena.encode('utf-8')
    hash_sha3 = hashlib.sha3_512(contrasena_bytes).hexdigest()
    return hash_sha3

# Función para verificar la contraseña
def verificar_contrasena_sin_hash(conexion, usuario, contrasena_ingresada):
    try:
        cursor = conexion.cursor()
        query = "SELECT contrasena FROM usuarios WHERE nombre_usuario = %s"
        cursor.execute(query, (usuario,))
        resultado = cursor.fetchone()

        if resultado:
            contrasena_almacenada = resultado[0]
            contrasena_ingresada = hashear_contrasena_sha3(contrasena_ingresada)
            return contrasena_ingresada == contrasena_almacenada
        else:
            print("Error: Usuario no encontrado.")
            return False
    except Error as e:
        print(f"Error durante la verificación de la contraseña: {e}")
        return False

# Verificar HMAC (MAC)
def verificar_mac(mensaje, nonce, mac_cliente):
    mensaje_con_nonce = mensaje + nonce
    mac_servidor = hmac.new(CLAVE_SECRETA, mensaje_con_nonce.encode('utf-8'), hashlib.sha512).hexdigest()
    return hmac.compare_digest(mac_servidor, mac_cliente)

# Verificar si el nonce ha sido usado:
def verificar_nonce_usado(nonce, nonces_usados):
    if nonce in nonces_usados:
        return True
    else:
        return False

# Leer los nonces usados desde el archivo
def leer_nonces_usados():
    if os.path.exists(NONCE_FILE):
        with open(NONCE_FILE, 'r') as file:
            nonces = file.read().splitlines()
            return set(nonces)
    return set()

# Guardar un nonce en el archivo
def guardar_nonce(nonce):
    with open(NONCE_FILE, 'a') as file:
        file.write(nonce + "\n")

# Comprobar si los IBAN son validos:
def iban_valido(origen, destino):
    if(len(origen) == 24 and len(destino) == 24 and origen != destino):
        return True
    else:
        return False

# Comprobar si la cantidad es valida:
def cantidad_valida(cantidad):
    try:
        cantidad = int(cantidad)
    except:
        return False   
    if cantidad <0:
        return False
    else:
        return True

# Crear el socket del servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Servidor en espera de conexiones...")

    conn, addr = s.accept()
    with conn:
        print(f"Conectado con {addr}")

        # Conectar a la base de datos
        conexion = conectar_base_datos()
        if not conexion:
            conn.sendall(b"Error al conectar con la base de datos")
            conn.close()

        while True:
            # Recibir datos del cliente
            data = conn.recv(1024)
            if not data:
                break

            # Decodificar los datos recibidos (usuario, contraseña)
            datos_recibidos = data.decode('utf-8').split(':')
            if len(datos_recibidos) != 2:
                conn.sendall(b"Error: Datos mal formateados.")
                continue

            usuario, contraseña = datos_recibidos

            # Verificar si el usuario existe y la contraseña es correcta
            if usuario_existe(conexion, usuario) and verificar_contrasena_sin_hash(conexion, usuario, contraseña):
                mensaje_a_verificar = f"{usuario}:{contraseña}"
                print("Usuario autenticado")
                conn.sendall(b"Enviado con exito")
                # Esperar el mensaje de transferencia
                mensaje_transferencia = conn.recv(1024)
                # Decodificar la transferencia (mensaje, mac_cliente, nonce)
                transferncia_recibida = mensaje_transferencia.decode('utf-8').split(':')
                #  Comprobamos errores de transferencia
                if len(transferncia_recibida) != 6:
                    conn.sendall(b"Error: Transferencia mal formateados.")
                    continue
                                
                mensaje, origen, destino, cantidad, mac_cliente, nonce = transferncia_recibida
                
                # Verificacion de errores en el mensaje (MAC, NONCE, IBAN, CANTIDAD)           
                # Transferencia Validada:     
                if verificar_mac(mensaje, nonce, mac_cliente) and iban_valido(origen, destino) and (not (verificar_nonce_usado(nonce, leer_nonces_usados()))) and cantidad_valida(cantidad):
                    print("Transferencia Validada!")
                    conn.sendall(b"Transferencia Validada!")
                    guardar_nonce(nonce)
                # Errores en la transferencia:
                else:
                    # Error en la MAC(Cierre de la conexion): 
                    if(not verificar_mac(mensaje, nonce, mac_cliente)):
                        print("Error: MAC inválido.")
                        conn.sendall(b"Error: MAC invalido.")
                    # Error en el NONCE(Cierre de la conexion): 
                    elif(verificar_nonce_usado(nonce, leer_nonces_usados())):
                        print("Error: NONCE ya usado.")
                        conn.sendall(b"Error: NONCE ya usado.")
                    # Errores en el iban o en la cantidad (Solicitamos nueva entrada de datos):
                    elif(not iban_valido(origen, destino) or not cantidad_valida(cantidad)):
                        # Bucle error en iban:
                        while(not iban_valido(origen, destino)):
                            print("Error: Iban invalido.")
                            conn.sendall(b"Error: Iban invalido.")
                            mensaje_transferencia = conn.recv(1024)
                            transferncia_recibida = mensaje_transferencia.decode('utf-8').split(':')
                            mensaje, origen, destino, cantidad, mac_cliente, nonce = transferncia_recibida
                        # Bucle error en la cantidad:
                        while(not cantidad_valida(cantidad)):
                            print("Error: Cantidad inválida.")
                            conn.sendall(b"Error: Cantidad invalida.")
                            mensaje_transferencia = conn.recv(1024)
                            transferncia_recibida = mensaje_transferencia.decode('utf-8').split(':')
                            mensaje, origen, destino, cantidad, mac_cliente, nonce = transferncia_recibida
                        # Errores corregidos (Transferencia Validada):
                        print("Transferencia Validada!")
                        conn.sendall(b"Transferencia Validada!")
                        guardar_nonce(nonce)
                    break
            else:
                conn.sendall(b"Error: Usuario o contrasena incorrectos.")
                break

        # Cerrar la conexión a la base de datos
        if conexion.is_connected():
            conexion.close()
