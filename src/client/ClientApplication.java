package client;

import java.nio.charset.StandardCharsets;
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
        client.ClientCryptoService hsm = new ClientCryptoService(hsmIp, hsmUser, hsmUserPassword);

        // III - Gerar chave assimetrica e enviar a parte publica para o servidor
        hsm.CreateKey(AssymKeyId, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
        byte[] pbLocalKey = hsm.exportKey(AssymKeyId, TacNDJavaLib.PUBLICKEY_BLOB);
        comm.sendMessage(pbLocalKey);

        // IV - Recebe a chave publica do servidor, gera a chave derivada e a de sessao
        byte[] pbServerPubKey = comm.readMessage();
        byte[] pbKDFData = "O QUE FAZEMOS EM VIDA ECOA PELA ETERNIDADE".getBytes(StandardCharsets.UTF_8); // Conteudo acordado entre ambas as partes
        hsm.genECDHKey(sessionKey, AssymKeyId, pbServerPubKey, pbKDFData);                     

        // V - Recebe uma mensagem cifrada do servidor e a decifra
        byte[] encryptedMessage = comm.readMessage();
        byte[] decryptedMessage = hsm.decryptMessage(sessionKey, encryptedMessage);
        String serverMessage = new String(decryptedMessage, StandardCharsets.UTF_8); // remontando a mensagem (bytes -> string)
        System.out.println("Mensagem recebida: " + serverMessage);

        // VI - Gera par de chaves de assinatura digital
        hsm.CreateKey(clientSignatureKey, TacNDJavaLib.ALG_ECC_SECP256R1);
        byte[] public_clientSignatureKey= hsm.exportKey(clientSignatureKey, TacNDJavaLib.PUBLICKEY_BLOB); // Parte publica da chave

        // VII - Assina digitalmente a mensagem, encripta tudo e envia ao servidor
        byte[] signature = hsm.signMessage(clientSignatureKey, TacNDJavaLib.ALG_SHA2_256, decryptedMessage);

        byte[] encryptedMessage2 = hsm.encryptMessage(sessionKey, decryptedMessage);
        byte[] encryptedSignature = hsm.encryptMessage(sessionKey, signature);
        byte[] encryptedPubSignKey = hsm.encryptMessage(sessionKey, public_clientSignatureKey);

        comm.sendMessage(encryptedMessage2);
        comm.sendMessage(encryptedSignature);
        comm.sendMessage(encryptedPubSignKey);

        // --- Encerramento do processo cliente ---
        
        System.out.println("Excluindo chaves de sessao");
        hsm.deleteKey(AssymKeyId);
        hsm.deleteKey(sessionKey);
        hsm.deleteKey(clientSignatureKey);
        
        hsm.close();  // Fecha a conexao com o servidor HSM
        comm.close(); // Fecha a conexao com o servidor
    }
}
