package examples;
import java.util.Arrays;
 
import com.dinamonetworks.Dinamo;
 
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
 
public class GenEcdhKeyX963 {
    private static String strAddr   = "187.33.9.132";
    private static String strUsrId  = "utfpr1";
    private static String strPwd    = "segcomp20241";

    private static String strLocalKey   = "test_local_key";
    private static String strPeerKey    = "test_peer_key";
    private static String strTargetKey  = "test_target_key";
    private static String strSessionKey = "test_session_key";
 
    public static void main(String[] args) {
 
        Dinamo api = new Dinamo();
 
        try {
            api.openSession(strAddr, strUsrId, strPwd);
 
            api.deleteKeyIfExists(strLocalKey);
            api.deleteKeyIfExists(strTargetKey);
            api.deleteKeyIfExists(strSessionKey);
            api.deleteKeyIfExists(strPeerKey);
 
            System.out.println("--> Generate ECDH keys!");
            api.createKey(strLocalKey, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
            api.createKey(strPeerKey, TacNDJavaLib.ALG_ECC_BRAINPOOL_P512T1);
 
            System.out.println("--> Export public key from peer key!");
            byte[] pbPeerPubKey = api.exportKey(strPeerKey, TacNDJavaLib.PUBLICKEY_BLOB);
 
            byte[] pbKDFData = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,
                    (byte)0x11,(byte)0x12,(byte)0x13,(byte)0x14,(byte)0x15,(byte)0x16,(byte)0x17,(byte)0x18};
 
            /*
             * Primeira forma de gerar a chave.
             *
             * Gera a chave derivada e guarda dentro do HSM.
             * */
 
            System.out.println("--> Generate shared secret!");
            api.genEcdhKeyX963Sha256(strLocalKey,
                                    strTargetKey,
                                    TacNDJavaLib.ALG_AES_256,
                                    true,
                                    false,
                                    pbPeerPubKey,
                                    pbKDFData);
 
            /*
             * Segunda forma de gerar a chave.
             *
             * Gera a chave derivada dentro do HSM e devolve ao chamador sem adiciona-la ao HSM.
             * Como os parâmetros são iguais as chaves geradas são iguais.
             * */
 
            System.out.println("--> Generate shared secret! (2nd option)");
            byte[] pbKey = api.genEcdhKeyX963Sha256(strLocalKey, //chave local
                                                    null,        // Nome da chave derivada, caso fosse chamar
                                                    TacNDJavaLib.ALG_AES_256, //tipo da chave (eu acho)
                                                    false,
                                                    false,
                                                    pbPeerPubKey,   // Chave publica do outro
                                                    pbKDFData);     // Informacao compartilhada para gerar a chave   
 
            byte[] pbClearBuffer = "askdfkasdfaksdfa".getBytes(); // Texto de exemplo para testar as chaves
 
            /*
             * Importa a chave com o conteúdo retornado.
             * */
 
            System.out.println("--> Import shared secret!");
            // Aqui ele cria a chave privada compartilhada
            api.importKey(  strSessionKey, // nome da chave
                            TacNDJavaLib.PLAINTEXTKEY_BLOB,
                            TacNDJavaLib.ALG_AES_256,
                            TacNDJavaLib.EXPORTABLE_KEY,
                            pbKey, // a partir da chave derivada que achamos
                            TacNDJavaLib.ALG_AES_256_LEN);
 
            System.out.println("--> Encrypt and decrypt buffer!");
            byte[] pbEncryptedBuffer = api.encrypt(strSessionKey, pbClearBuffer);
            byte[] pbDecryptedBuffer = api.decrypt(strTargetKey, pbEncryptedBuffer);
 
            if(!Arrays.equals(pbClearBuffer, pbDecryptedBuffer))
            {
                System.out.println("Decrypted buffer and clear text buffer are different!");
            }
 
            System.out.println("--> Delete keys!");
            api.deleteKey(strLocalKey);
            api.deleteKey(strPeerKey);
            api.deleteKey(strTargetKey);
            api.deleteKey(strSessionKey);
 
            api.closeSession();
        } catch (TacException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
