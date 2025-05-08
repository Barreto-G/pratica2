package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Base64;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerCommunicationService implements AutoCloseable{
    private PrintWriter out;
    private BufferedReader in;
    private Socket clientSocket;
    private ServerSocket serverSocket;

    public ServerCommunicationService(int port) throws IOException{
        this.serverSocket = new ServerSocket(port);
        System.out.println("Servidor estabelecido com sucesso!\n Escutando na porta: " + port);
    }

    public boolean listen() throws IOException{
        try {
            this.clientSocket = this.serverSocket.accept();
            System.out.println("Conectado a cliente");
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);
            this.in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            return true;
        } catch (Exception e) {
            System.out.println("Nao foi possivel estabelecer conexao com cliente, tente novamente.");
            return false;
        }
    }

    @Override
    public void close() throws Exception {
        System.out.println("Encerrando conexao com o servidor");
        this.out.close();
        this.in.close();
        this.clientSocket.close();
        this.serverSocket.close();
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