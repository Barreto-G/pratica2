package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.dinamonetworks.Dinamo;

import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;

public class ServerApplication {
     public static void main(String[] args) throws IOException, TacException {
        // I - Lancamento do servidor e conexao com o cliente
        int port = 54000; // Porta onde o servidor vai ouvir
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Servidor ouvindo na porta " + port);

        Socket clientSocket = serverSocket.accept(); // Espera a conexão do cliente
        System.out.println("Cliente conectado!");

        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // II - Conecta com o Dinamo
        String hsmIp = "187.33.9.132";
        String hsmUser = "utfpr1";
        String hsmUserPassword = "segcomp20241";

        Dinamo api = new Dinamo();
        api.openSession(hsmIp, hsmUser, hsmUserPassword);
        System.out.println("API dinamo se conectou com sucesso!");

        // III - Gera conjunto de chaves assimetricas e envia a chave publica para o cliente
        String AssymKeyId = "asymServerKey_gb";
        api.deleteKeyIfExists(AssymKeyId);

        api.createKey(AssymKeyId, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
        byte[] pbLocalKey = api.exportKey(AssymKeyId, TacNDJavaLib.PUBLICKEY_BLOB);
        String pbLocalKeyBase64 = Base64.getEncoder().encodeToString(pbLocalKey);
        out.println(pbLocalKeyBase64);

        // IV - Recebe chave publica do cliente e constroi a chave derivada
        String pbClientPubKeyBase64 = in.readLine();
        byte[] pbClientPubKey = Base64.getDecoder().decode(pbClientPubKeyBase64);
        // Conteudo acordado entre ambas as partes
        byte[] pbKDFData = "O QUE FAZEMOS EM VIDA ECOA PELA ETERNIDADE".getBytes(StandardCharsets.UTF_8);

        byte[] pbKey = api.genEcdhKeyX963Sha256(AssymKeyId, //chave local
                                                    null,        // Nome da chave derivada, caso fosse salvar
                                                    TacNDJavaLib.ALG_AES_256, //tipo da chave (eu acho)
                                                    false,
                                                    false,
                                                    pbClientPubKey,   // Chave publica do outro
                                                    pbKDFData);     // Informacao compartilhada para gerar a chave

        // V - Gera chave de sessao a partir da chave derivada
        String sessionKey = "serverSessionKey_gb";
        api.deleteKeyIfExists(sessionKey);

        api.importKey(sessionKey,
                    TacNDJavaLib.PLAINTEXTKEY_BLOB,
                    TacNDJavaLib.ALG_AES_256,
                    TacNDJavaLib.EXPORTABLE_KEY,
                    pbKey,
                    TacNDJavaLib.ALG_AES_256_LEN);
        
        // VI - Cifra uma mensagem e envia para o cliente
        String message = "O RATO ROEU A ROUPA DO REI DE ROMA";
        byte[] bMessage = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = api.encrypt(sessionKey, bMessage);
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);

        out.println(encryptedMessageBase64);

        // VII - Espera o retorno do cliente
        String messageBase64 = in.readLine();
        String signatureBase64 = in.readLine();
        String pubSignKeyBase64 = in.readLine();

        byte[] message_encrypted = Base64.getDecoder().decode(messageBase64);
        byte[] signature_encrypted = Base64.getDecoder().decode(signatureBase64);
        byte[] pubSignKey_encrypted = Base64.getDecoder().decode(pubSignKeyBase64);

        byte[] message_decrypted = api.decrypt(sessionKey, message_encrypted);
        byte[] signature_decrypted = api.decrypt(sessionKey, signature_encrypted);
        byte[] pubSignKey_decrypted = api.decrypt(sessionKey, pubSignKey_encrypted);

        // VIII - Verifica se a assinatura digital e valida
        String clientPublicKey = "client_pubkey_tmp";
        api.deleteKeyIfExists(clientPublicKey);
        System.out.println("Até aqui de boa");
        
        try {
            api.importKey(clientPublicKey, 
                    TacNDJavaLib.PUBLICKEY_BLOB, 
                    TacNDJavaLib.ALG_ECC_SECP256R1,
                    TacNDJavaLib.EXPORTABLE_KEY,  
                    pubSignKey_decrypted,
                    pubSignKeyBase64.length()
            );
            

            api.verifySignature(clientPublicKey, TacNDJavaLib.ALG_SHA2_256, signature_decrypted, message_decrypted);
            System.out.println("Assinatura válida!");
        } catch (TacException e) {
            System.out.println("Assinatura invalida ou erro de importacao da chave");
            System.out.println(e.getMessage());
        }

        System.out.println("Excluindo chaves de sessao");
        api.deleteKey(AssymKeyId);
        api.deleteKey(sessionKey);
        api.deleteKeyIfExists(clientPublicKey);
        
        System.out.println("Encerrando conexao com cliente e fechando servidor");
        clientSocket.close(); // Fecha a conexão com o cliente (ou mantenha aberto se quiser)
        serverSocket.close();
    }
}
