package BYOD;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

public class BYODClient {
	
	/**
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		try {
			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) factory.createSocket("0.0.0.0", 3343);
			
			// BufferedReader para recibir la respuesta del servidor
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			// PrintWriter para enviar datos al servidor
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

			// Pedir usuario y contraseña al usuario
			String username = JOptionPane.showInputDialog(null, "Enter username:");
			String password = JOptionPane.showInputDialog(null, "Enter password:");
			
			// Enviar usuario y contraseña al servidor
			output.println(username);
			output.println(password);
			output.flush();

			// Leer la respuesta del servidor
			String response = input.readLine();
			
			System.out.println("Cypher Suite: "+ socket.getSession().getCipherSuite());

			if ("Authenticated".equals(response)) {
				// Si la autenticación es correcta, permitir enviar un mensaje
				String msg = JOptionPane.showInputDialog(null, "Enter a message to send:");
				output.println(msg);
				output.flush();
				// Leer respuesta del servidor al mensaje
				response = input.readLine();
				JOptionPane.showMessageDialog(null, response);
			} else {
				// Si la autenticación falla, mostrar mensaje de error
				JOptionPane.showMessageDialog(null, "Authentication failed.");
			}

			// Cerrar streams y el socket
			output.close();
			input.close();
			socket.close();

		} catch (IOException ioException) {
			ioException.printStackTrace();
		} finally {
			System.exit(0);
		}
	}

}
