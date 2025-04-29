package client;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.dinamonetworks.Dinamo;

import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;

public class ClientApplication {
    public static void main(String[] args) throws IOException, TacException{
        // I - Conexao com o servidor
        String serverAddress = "localhost";
        int port = 54000;

        Socket socket = new Socket(serverAddress, port);;
        System.out.println("Conectado ao servidor com sucesso!");
        
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // II - Conexao com a API da Dinamo
        String hsmIp = "187.33.9.132";
        String hsmUser = "utfpr1";
        String hsmUserPassword = "segcomp20241";

        Dinamo api = new Dinamo();
        api.openSession(hsmIp, hsmUser, hsmUserPassword);
        System.out.println("API dinamo se conectou com sucesso!");

        // III - Gerar chave assimetrica e enviar a parte publica para o servidor
        String AssymKeyId = "asymClientKey_gb";
        api.deleteKeyIfExists(AssymKeyId);

        client.ClientCryptoService.CreateKey(api,AssymKeyId, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
        byte[] pbLocalKey = client.ClientCryptoService.GetPublicKey(api, AssymKeyId); 
        String pbLocalKeyBase64 = Base64.getEncoder().encodeToString(pbLocalKey);
        out.println(pbLocalKeyBase64);

        // IV - Recebe a chave publica do servidor e gera a chave derivada
        String pubKeyBase64 = in.readLine();
        byte[] pbServerPubKey = Base64.getDecoder().decode(pubKeyBase64);

        // Conteudo acordado entre ambas as partes
        byte[] pbKDFData = "O QUE FAZEMOS EM VIDA ECOA PELA ETERNIDADE".getBytes(StandardCharsets.UTF_8);

        byte[] pbKey = api.genEcdhKeyX963Sha256(AssymKeyId, //chave local
                                                    null,        // Nome da chave derivada, caso fosse salvar
                                                    TacNDJavaLib.ALG_AES_256, //tipo da chave (eu acho)
                                                    false,
                                                    false,
                                                    pbServerPubKey,   // Chave publica do outro
                                                    pbKDFData);     // Informacao compartilhada para gerar a chave   


        // V - Gera a chave de sessao a partir da chave derivada                                           
        String sessionKey = "clientSessionKey_gb";
        api.deleteKeyIfExists(sessionKey);

        api.importKey(sessionKey, // nome da chave
                    TacNDJavaLib.PLAINTEXTKEY_BLOB,
                    TacNDJavaLib.ALG_AES_256,
                    TacNDJavaLib.EXPORTABLE_KEY,
                    pbKey, // a partir da chave derivada que achamos
                    TacNDJavaLib.ALG_AES_256_LEN);
        
        // VI - Recebe uma mensagem cifrada do servidor e a decifra
        String encryptedMessageBase64 = in.readLine();
        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);
        byte[] decryptedMessage = api.decrypt(sessionKey, encryptedMessage);
        String serverMessage = new String(decryptedMessage, StandardCharsets.UTF_8); 

        System.out.println("Mensagem recebida: " + serverMessage);

        // VII - Gera par de chaves de assinatura digital
        String clientSignatureKey = "ClientSigKey_gb";
        api.deleteKeyIfExists(clientSignatureKey);
        api.createKey(clientSignatureKey, TacNDJavaLib.ALG_ECC_SECP256R1);

        byte[] public_clientSignatureKey = api.exportKey(clientSignatureKey, TacNDJavaLib.PUBLICKEY_BLOB);

        // VIII - Assina digitalmente a mensagem envia novamente ao servidor
        byte[] signature = api.signHash(clientSignatureKey, TacNDJavaLib.ALG_SHA2_256, decryptedMessage);

        byte[] encryptedMessage2 = api.encrypt(sessionKey, decryptedMessage);
        byte[] encryptedSignature = api.encrypt(sessionKey, signature);
        byte[] encryptedPubSignKey = api.encrypt(sessionKey, public_clientSignatureKey);

        String encryptedMessage2_Base64 = Base64.getEncoder().encodeToString(encryptedMessage2);
        String encryptedSignature_Base64 = Base64.getEncoder().encodeToString(encryptedSignature);
        String encryptedPubSignKey_Base64 = Base64.getEncoder().encodeToString(encryptedPubSignKey);

        out.println(encryptedMessage2_Base64);
        out.println(encryptedSignature_Base64);
        out.println(encryptedPubSignKey_Base64);

        
        System.out.println("Excluindo chaves de sessao");
        api.deleteKey(AssymKeyId);
        api.deleteKey(sessionKey);
        api.deleteKey(clientSignatureKey);

        System.out.println("Encerrando conexao com servidor");
        socket.close();
    }
}
