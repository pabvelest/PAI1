package BYOD;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

public class BYODClient {
    
    private static final int NUM_CLIENTS = 1000;

    /**
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException, InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(NUM_CLIENTS);

        for (int i = 0; i < NUM_CLIENTS; i++) {
            int clientId = i + 1;
            executorService.submit(() -> {
                try {
                    runClient(clientId); // Llamada a la función del cliente
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }

        // Esperar a que todas las tareas se completen
        executorService.shutdown();
    }

    private static void runClient(int clientId) throws IOException {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            //SSLSocket socket = (SSLSocket) factory.createSocket("localhost",3343);
            SSLSocket socket = (SSLSocket) factory.createSocket("0.0.0.0", 3343);

            // BufferedReader para recibir la respuesta del servidor
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // PrintWriter para enviar datos al servidor
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

            String username = "user4";
            String password = "PaquitoAAA";

            // Enviar usuario y contraseña al servidor
            output.println(username);
            output.println(password);
            output.flush();

            // Leer la respuesta del servidor
            String response = input.readLine();

            System.out.println("Cliente " + clientId + " - Cypher Suite: " + socket.getSession().getCipherSuite());

            if ("Authenticated".equals(response)) {
                // Si la autenticación es correcta, permitir enviar un mensaje
                String msg = "Hola desde el cliente " + clientId;
                output.println(msg);
                output.flush();

                // Leer respuesta del servidor al mensaje
                response = input.readLine();
                System.out.println("Cliente " + clientId + ": " + response);
            } else {
                // Si la autenticación falla, mostrar mensaje de error
                System.out.println("Cliente " + clientId + ": Authentication failed.");
            }

            // Cerrar streams y el socket
            output.close();
            input.close();
            socket.close();

        } catch (IOException ioException) {
            System.err.println("Error en el cliente " + clientId);
            ioException.printStackTrace();
        }
    }
}
