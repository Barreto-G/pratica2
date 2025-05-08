package server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;

public class ServerApplication {
    static int port = 54000; // Porta onde o servidor vai ouvir
    static String hsmIp = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmUserPassword = "segcomp20241";
    static String agreedString = "O QUE FAZEMOS EM VIDA ECOA PELA ETERNIDADE";

    static String AssymKeyId = "asymServerKey_gb";
    static String sessionKey = "serverSessionKey_gb";
    static String clientPublicKey = "client_pubkey_gb";
    static String clientSignatureKey = "clientSignKey_gb";

    public static void main(String[] args) throws IOException, TacException {
        // I - Lancamento do servidor e conexao com o cliente
        server.ServerCommunicationService comm = new ServerCommunicationService(port);
        while(!comm.listen()){}

        // II - Conecta com o Dinamo
        server.ServerCryptoService hsm = new ServerCryptoService(hsmIp, hsmUser, hsmUserPassword);

        // III - Gera conjunto de chaves assimetricas e envia a chave publica para o cliente
        
        hsm.CreateKey(AssymKeyId, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
        byte[] pbLocalKey = hsm.exportKey(AssymKeyId, TacNDJavaLib.PUBLICKEY_BLOB);
        comm.sendMessage(pbLocalKey);

        // IV - Recebe chave publica do cliente e constroi a chave de sessao
        byte[] pbClientPubKey = comm.readMessage();
        byte[] pbKDFData = agreedString.getBytes(StandardCharsets.UTF_8); // Conteudo acordado entre ambas as partes
        hsm.genECDHKey(sessionKey, AssymKeyId, pbClientPubKey, pbKDFData); 

        // V - Cifra uma mensagem e envia para o cliente
        byte[] bMessage = "O RATO ROEU A ROUPA DO REI DE ROMA".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = hsm.encryptMessage(sessionKey, bMessage);
        comm.sendMessage(encryptedMessage);

        // VI - Espera o retorno do cliente
        byte[] message = comm.readMessage();
        message = hsm.decryptMessage(sessionKey, message);

        byte[] signature = comm.readMessage();
        signature = hsm.decryptMessage(sessionKey, signature);

        byte[] pubSignKey = comm.readMessage();
        pubSignKey = hsm.decryptMessage(sessionKey, pubSignKey);

        // VII - Verifica se a assinatura digital e valida
        hsm.importKey(clientSignatureKey, 
                    TacNDJavaLib.PUBLICKEY_BLOB_HSM, 
                    TacNDJavaLib.EXPORTABLE_KEY, 
                    TacNDJavaLib.ALG_OBJ_PUBKEY_ECC_BLOB, 
                    pubSignKey, 
                    pubSignKey.length);

        hsm.verifySignature(clientSignatureKey, 
                            TacNDJavaLib.ALG_SHA2_256, 
                            signature, 
                            message);

        // VIII - Excluindo chaves criadas e encerrando processos
        System.out.println("Excluindo chaves de sessao");
        hsm.deleteKey(AssymKeyId);
        hsm.deleteKey(sessionKey);
        hsm.deleteKey(clientPublicKey);
        hsm.deleteKey(clientSignatureKey);

        
        System.out.println("Encerrando conexao com cliente e fechando servidor");
        try {
            hsm.close();
            comm.close();
            System.out.println("Processo servidor encerrado com sucesso!");
        } catch (Exception e) {
            System.out.println("Houve um problema ao encerrar as conexões do servidor");
            System.out.println(e.getMessage());
        }
    }
}
