package BYOD;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class BYODServer {

    private static final HashMap<String, String> userDatabase = new HashMap<>();
    private static final int MAX_CLIENTS = 300;  // Número máximo de clientes permitidos
    private static int clientCount = 0;  // Contador de clientes

    public static void main(String[] args) throws IOException, InterruptedException {
        // Cargar usuarios y hashes de contraseñas desde el archivo CSV
        loadUserDatabase("C:\\Users\\guill\\Desktop\\Users.csv");

        try {        
            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(3343, 1000, InetAddress.getByName("0.0.0.0"));

            while (true) {  
                synchronized (BYODServer.class) {
                    if (clientCount >= MAX_CLIENTS) {
                        System.err.println("Capacidad máxima de 300 clientes alcanzada. No se permiten más conexiones.");
                        // Esperar un tiempo o realizar alguna acción específica cuando se alcanza el límite
                        Thread.sleep(1000);
                        continue;  // Saltar a la siguiente iteración del bucle sin aceptar conexiones
                    }
                }

                System.err.println("Waiting for connection...");
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                
                // Incrementar el contador de clientes de forma sincronizada
                incrementClientCount();

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

                // Leer usuario y contraseña enviados por el cliente
                String username = input.readLine();
                String password = input.readLine();

                // Verificar usuario y contraseña
                if (authenticateUser(username, password)) {
                    output.println("Authenticated");
                    output.flush();

                    // Esperar mensaje del cliente y responder
                    String clientMsg = input.readLine();
                    System.out.println("Client message: " + clientMsg);
                    output.println("Message received: " + clientMsg);
                } else {
                    output.println("Authentication failed");
                }

                output.close();
                input.close();
                socket.close();
            }

        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    private static void incrementClientCount() {
        // Incrementar el contador de clientes de forma segura en entornos concurrentes
        synchronized (BYODServer.class) {
            clientCount++;
            System.out.println("Número de clientes conectados: " + clientCount);
        }
    }

    private static void loadUserDatabase(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Remover espacios en blanco al inicio y al final de la línea
                line = line.trim();

                // Omitir líneas vacías
                if (line.isEmpty()) continue;
                
                // Separar los datos por coma
                String[] values = line.split(";", 2); // Limitar a 2 elementos en caso de que haya comas adicionales

                // Validar que se hayan encontrado exactamente 2 valores
                if (values.length == 2) {
                    // Limpiar el nombre de usuario de caracteres no deseados
                    String username = cleanInput(values[0].trim());
                    String passwordHash = values[1].trim();

                    // Verificar que no estén vacíos antes de agregarlos
                    if (!username.isEmpty() && !passwordHash.isEmpty()) {
                        // Agregar el usuario y el hash al mapa userDatabase
                        userDatabase.put(username, passwordHash);
                        System.out.println("Usuario: " + username + ", Hash de Contraseña: " + passwordHash);
                    } else {
                        System.err.println("Línea con valores vacíos: " + line);
                    }
                } else {
                    System.err.println("Línea con formato incorrecto: " + line);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading the users file: " + e.getMessage());
        }
    }

    // Método para limpiar el input de caracteres no deseados
    private static String cleanInput(String input) {
        // Eliminar caracteres no alfanuméricos y permitir guiones bajos
        return input.replaceAll("[^a-zA-Z0-9_]", "");
    }

    private static boolean authenticateUser(String username, String password) {
        // Obtener el hash SHA3-512 de la contraseña proporcionada
        String hashedPassword = hashPassword(password);

        // Verificar que el usuario exista y que el hash de la contraseña coincida
        return userDatabase.containsKey(username) && userDatabase.get(username).equals(hashedPassword);
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA3-512");
            byte[] hashBytes = digest.digest(password.getBytes());
            StringBuilder hashString = new StringBuilder();
            for (byte b : hashBytes) {
                hashString.append(String.format("%02x", b));
            }
            return hashString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating password hash", e);
        }
    }

}
