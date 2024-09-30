import socket
import mysql.connector
import hashlib
from mysql.connector import Error

HOST = "127.0.0.1"
PORT = 3030

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
    # Convertir la contraseña a formato bytes
    contrasena_bytes = contrasena.encode('utf-8')
    
    # Crear el hash con SHA3-256
    hash_sha3 = hashlib.sha3_512(contrasena_bytes).hexdigest()
    
    return hash_sha3

def verificar_contrasena_sin_hash(conexion, usuario, contrasena_ingresada):
    try:
        cursor = conexion.cursor()
        # Buscar la contraseña almacenada para el usuario
        query = "SELECT contrasena FROM usuarios WHERE nombre_usuario = %s"
        cursor.execute(query, (usuario,))
        resultado = cursor.fetchone()

        if resultado:
            contrasena_almacenada = resultado[0] 
            # Comparar la contraseña ingresada con la almacenada
            contrasena_ingresada=hashear_contrasena_sha3(contrasena_ingresada)
            print(contrasena_ingresada)
            #print(contrasena_almacenada)
            if contrasena_ingresada == contrasena_almacenada:
                return True
            else:
                print("Error: Contraseña incorrecta.")
                return False
        else:
            print("Error: Contraseña incorrecta.")
            return False
    except Error as e:
        print(f"Error durante la verificación de la contraseña: {e}")
        return False    

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

            # Decodificar los datos recibidos
            datos_recibidos = data.decode('utf-8')
            try:
                usuario, contraseña = datos_recibidos.split(':')
            except ValueError:
                conn.sendall(b"Error: Datos mal formateados.")
                continue

            # Verificar si el usuario existe en la base de datos
            if usuario_existe(conexion, usuario) and verificar_contrasena_sin_hash(conexion, usuario, contraseña):
                # Verificar credenciales
                print("Usuario autenticado!")
                conn.sendall(b"Enviado con exito")

                # Esperar el mensaje de transferencia
                mensaje_transferencia = conn.recv(1024).decode('utf-8')
                print(f"Mensaje de transferencia recibido: {mensaje_transferencia}")
                
                # Aquí puedes realizar cualquier acción necesaria con el mensaje recibido
                
                conn.sendall(b"Mensaje de transferencia recibido con exito.")
            else:
                if not usuario_existe(conexion, usuario):
                    print(f"Usuario no encontrado: {usuario}")
                    conn.sendall(b"Error: Usuario no encontrado.")
                    break
                else:
                    print(f"Contraseña Incorrecta")
                    conn.sendall(b"Error: Contrasena incorrecta.")
                    break

        # Cerrar la conexión a la base de datos
        if conexion.is_connected():
            conexion.close()
