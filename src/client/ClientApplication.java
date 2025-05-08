package client;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import br.com.trueaccess.TacNDJavaLib;
import common.JsonReader;

public class ClientApplication {
    

    public static void main(String[] args) throws Exception{
        // O - Lendo informacoes do Json
        Map<String, String> info = JsonReader.ReadJson("data/clientData.json");

        String serverAddress = info.get("serverAddress");
        int port = Integer.parseInt(info.get("port"));

        String hsmIp = info.get("hsmIp");
        String hsmUser = info.get("hsmUser");
        String hsmUserPassword = info.get("hsmUserPassword");

        String agreedString = info.get("agreedString");
        String AssymKeyId = info.get("AssymKeyId");
        String sessionKey = info.get("sessionKey");
        String clientSignatureKey = info.get("clientSignatureKey");
            
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
        byte[] pbKDFData = agreedString.getBytes(StandardCharsets.UTF_8); // Conteudo acordado entre ambas as partes
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
