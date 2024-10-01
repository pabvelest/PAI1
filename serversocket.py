import socket
import mysql.connector
import hashlib
import hmac
import secrets
from mysql.connector import Error

HOST = "127.0.0.1"
PORT = 3030
CLAVE_SECRETA = b'supersecretkey'  # Clave secreta para HMAC (debería almacenarse de forma segura)

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

            # Mostrar el Nonce y el MAC recibidos

            # Verificar si el usuario existe y la contraseña es correcta
            if usuario_existe(conexion, usuario) and verificar_contrasena_sin_hash(conexion, usuario, contraseña):
                mensaje_a_verificar = f"{usuario}:{contraseña}"
                print("Usuario autenticado")
                conn.sendall(b"Enviado con exito")
                
                # Esperar el mensaje de transferencia
                mensaje_transferencia = conn.recv(1024)
                # Decodificar la transferencia (mensaje, mac_cliente, nonce)
                transferncia_recibida = mensaje_transferencia.decode('utf-8').split(':')
                
                if len(transferncia_recibida) != 3:
                    conn.sendall(b"Error: Transferencia mal formateados.")
                    continue
                
                mensaje, mac_cliente, nonce = transferncia_recibida
                
                print(f"Nonce recibido: {nonce}")
                print(f"MAC recibido (HMAC): {mac_cliente}")
                
                if verificar_mac(mensaje, nonce, mac_cliente):
                    print("Transferencia Validada!")
                    conn.sendall(b"Transferencia Validada!")
                else:
                    print("Error: MAC inválido.")
                    conn.sendall(b"Error: MAC invalido.")
                    break
            else:
                conn.sendall(b"Error: Usuario o contrasena incorrectos.")
                break

        # Cerrar la conexión a la base de datos
        if conexion.is_connected():
            conexion.close()
