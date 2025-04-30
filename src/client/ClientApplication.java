package client;

import java.nio.charset.StandardCharsets;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacNDJavaLib;

public class ClientApplication {
    static String serverAddress = "localhost";
    static int port = 54000;

    static String hsmIp = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmUserPassword = "segcomp20241";

    static String AssymKeyId = "asymClientKey_gb";
    static String sessionKey = "clientSessionKey_gb";
    static String clientSignatureKey = "clientSignKey_gb";

    public static void main(String[] args) throws Exception{
        // I - Conexao com o servidor
        client.ClientCommunicationService comm = new ClientCommunicationService(serverAddress, port);

        // II - Conexao com a API da Dinamo

        Dinamo api = new Dinamo();
        api.openSession(hsmIp, hsmUser, hsmUserPassword);
        System.out.println("API dinamo se conectou com sucesso!");

        // III - Gerar chave assimetrica e enviar a parte publica para o servidor
        
        api.deleteKeyIfExists(AssymKeyId);

        client.ClientCryptoService.CreateKey(api,AssymKeyId, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
        byte[] pbLocalKey = client.ClientCryptoService.GetPublicKey(api, AssymKeyId); 
        comm.sendMessage(pbLocalKey);

        // IV - Recebe a chave publica do servidor e gera a chave derivada
        byte[] pbServerPubKey = comm.readMessage();

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
        
        api.deleteKeyIfExists(sessionKey);

        api.importKey(sessionKey, // nome da chave
                    TacNDJavaLib.PLAINTEXTKEY_BLOB,
                    TacNDJavaLib.ALG_AES_256,
                    TacNDJavaLib.EXPORTABLE_KEY,
                    pbKey, // a partir da chave derivada que achamos
                    TacNDJavaLib.ALG_AES_256_LEN);
        
        System.out.println("Chave de sessao gerada com sucesso");
        
        // VI - Recebe uma mensagem cifrada do servidor e a decifra
        byte[] encryptedMessage = comm.readMessage();
        byte[] decryptedMessage = api.decrypt(sessionKey, encryptedMessage);
        String serverMessage = new String(decryptedMessage, StandardCharsets.UTF_8); 

        System.out.println("Mensagem recebida: " + serverMessage);

        // VII - Gera par de chaves de assinatura digital
        
        api.deleteKeyIfExists(clientSignatureKey);
        api.createKey(clientSignatureKey, TacNDJavaLib.ALG_ECC_SECP256R1);

        byte[] public_clientSignatureKey = api.exportKey(clientSignatureKey, TacNDJavaLib.PUBLICKEY_BLOB);

        // VIII - Assina digitalmente a mensagem envia novamente ao servidor
        byte[] signature = api.signHash(clientSignatureKey, TacNDJavaLib.ALG_SHA2_256, decryptedMessage);

        byte[] encryptedMessage2 = api.encrypt(sessionKey, decryptedMessage);
        byte[] encryptedSignature = api.encrypt(sessionKey, signature);
        byte[] encryptedPubSignKey = api.encrypt(sessionKey, public_clientSignatureKey);

        comm.sendMessage(encryptedMessage2);
        comm.sendMessage(encryptedSignature);
        comm.sendMessage(encryptedPubSignKey);
        
        System.out.println("Excluindo chaves de sessao");
        api.deleteKey(AssymKeyId);
        api.deleteKey(sessionKey);
        api.deleteKey(clientSignatureKey);

        System.out.println("Encerrando conexao com servidor");
        comm.close();
    }
}
