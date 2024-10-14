import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import javax.net.ssl.*;
import javax.swing.JOptionPane;

public class MsgSSLClientSocket {
	
	/**
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		try {

			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 3343);
			
			// create BufferedReader for reading server response
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			// create PrintWriter for sending login to server
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			// prompt user for user name
			String msg = JOptionPane.showInputDialog(null, "Enter a message:");

			// send user name to server
			output.println(msg);

			output.flush();

			// read response from server
			String response = input.readLine();

			// display response to user
			JOptionPane.showMessageDialog(null, response);

			// clean up streams and Socket
			output.close();
			input.close();
			socket.close();

		} // end try

		// handle exception communicating with server
		catch (IOException ioException) {
			ioException.printStackTrace();
		}

		// exit application
		finally {
			System.exit(0);
		}

	}
}
