import socket
import bcrypt
import mysql.connector
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

# Función para verificar las credenciales
def verificar_credenciales(conexion, usuario, contraseña):
    try:
        cursor = conexion.cursor()
        query = "SELECT contrasena FROM usuarios WHERE nombre_usuario = %s"
        cursor.execute(query, (usuario,))
        resultado = cursor.fetchone()

        if resultado:
            stored_hash = resultado[0]  # Recuperar el hash de la base de datos
            if bcrypt.checkpw(contraseña.encode('utf-8'), stored_hash.encode('utf-8')):
                return True
        return False
    except Error as e:
        print(f"Error durante la verificación de credenciales: {e}")
        return False

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
    
def verificar_contrasena_sin_hash(conexion, usuario, contrasena_ingresada):
    try:
        cursor = conexion.cursor()
        # Buscar la contraseña almacenada para el usuario
        query = "SELECT contrasena FROM usuarios WHERE nombre_usuario = %s"
        cursor.execute(query, (usuario,))
        resultado = cursor.fetchone()

        if resultado:
            contrasena_almacenada = resultado[0]  # Contraseña en texto plano almacenada
            # Comparar la contraseña ingresada con la almacenada
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

    # Aceptar conexiones
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
            usuario, contraseña, mensaje = datos_recibidos.split(':')

            # Verificar si el usuario existe en la base de datos
            if usuario_existe(conexion, usuario) and verificar_contrasena_sin_hash(conexion,usuario,contraseña):
                # Verificar credenciales
                if verificar_credenciales(conexion, usuario, contraseña):
                    print(f"Usuario autenticado: {usuario}")
                    print(f"Mensaje de transferencia: {mensaje}")
                    conn.sendall("Autenticación exitosa. Transferencia recibida.")
                else:
                    print(f"Contraseña incorrecta para el usuario: {usuario}")
                    conn.sendall("Error: Contraseña incorrecta. Intenta nuevamente.")
            else:

                if(usuario_existe(conexion,usuario)==False):
                    print(f"Usuario no encontrado: {usuario}")
                    conn.sendall(b"Error: Usuario no encontrado.")
                else:
                    print(f"Contraseña Incorrecta")
                    conn.sendall(b"Error: Contrasena incorrecta.")

        # Cerrar la conexión a la base de datos
        if conexion.is_connected():
            conexion.close()
