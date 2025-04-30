package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Base64;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientCommunicationService implements AutoCloseable{
    private PrintWriter out;
    private BufferedReader in;
    private Socket socket;

    public ClientCommunicationService(String server, int port) throws UnknownHostException, IOException{
        this.socket = new Socket(server, port);
        System.out.println("Conectado ao servidor com sucesso!");

        this.out = new PrintWriter(socket.getOutputStream(), true);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    @Override
    public void close() throws Exception {
        this.out.close();
        this.in.close();
        this.socket.close();
        System.out.println("Comunicacao encerrada com sucesso");
    }

    public void sendMessage(byte[] content){
        String encodedMessage = encodeBase64Bytes(content);
        this.out.println(encodedMessage);
        System.out.println("Mensagem enviada com sucesso");
    }

    public byte[] readMessage() throws IOException{
        String messageBase64 = this.in.readLine();
        System.out.println("Mensagem recebida com sucesso");
        return decodeBase64String(messageBase64);
    }

    public static byte[] decodeBase64String(String strBase64){
        return Base64.getDecoder().decode(strBase64);
    }

    public static String encodeBase64Bytes(byte[] content){
        return Base64.getEncoder().encodeToString(content);
    }
}
