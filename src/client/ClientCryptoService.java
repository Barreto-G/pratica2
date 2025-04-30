package client;
import com.dinamonetworks.Dinamo;

import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;

public class ClientCryptoService {
    private Dinamo api;

    public ClientCryptoService(String ip, String usr, String pwd) throws TacException{
        this.api = new Dinamo();
        this.api.openSession(ip, usr, pwd);
        System.out.println("Conectado ao HSM com sucesso!");
    }

    public void CreateKey(String id, int type) throws TacException{
        this.api.deleteKeyIfExists(id);
        this.api.createKey(id, type);
    }

    public void CreateKey(String id, int type, int opc_arg) throws TacException{
        this.api.deleteKeyIfExists(id);
        this.api.createKey(id, type, opc_arg);
    }

    public byte[] exportKey(String id, int blobType) throws TacException{
        return this.api.exportKey(id, blobType);
    }

    public void importKey(String keyId, int blobType, int flags, int alg_id, byte[] keyData, int keySize) throws TacException{
        this.api.importKey(keyId, blobType, alg_id, flags, keyData, keySize);
    }

    public void deleteKey(String keyId){
        try {
            this.api.deleteKey(keyId);
        } catch (TacException e) {
            System.out.println("Nao foi possivel excluir a chave.");
            System.out.println(e.getErrorString());
        }
    }

    public void genECDHKey(String SessionKeyID, String usrPrivtKeyId, byte[] svrPubKey, byte[] sharedInfo) throws TacException{
        byte[] pbKey = api.genEcdhKeyX963Sha256(usrPrivtKeyId, //chave local
                                                    null,        // Nome da chave derivada, caso fosse salvar
                                                    TacNDJavaLib.ALG_AES_256, //tipo da chave (eu acho)
                                                    false,
                                                    false,
                                                    svrPubKey,   // Chave publica do outro
                                                    sharedInfo  // Informacao compartilhada para gerar a chave 
        );       

        this.api.deleteKeyIfExists(SessionKeyID);
        api.importKey(SessionKeyID, // nome da chave
                TacNDJavaLib.PLAINTEXTKEY_BLOB,
                TacNDJavaLib.ALG_AES_256,
                TacNDJavaLib.EXPORTABLE_KEY,
                pbKey, // a partir da chave derivada que achamos
                TacNDJavaLib.ALG_AES_256_LEN
        );    
        
        System.out.println("Chave ECDH gerada com sucesso");
    }

    public byte[] encryptMessage(String keyId, byte[] message) throws TacException{
        return this.api.encrypt(keyId, message);
    }

    public byte[] decryptMessage(String keyId, byte[] encryptedData) throws TacException{
        return this.api.decrypt(keyId, encryptedData);
    }

    public byte[] signMessage(String keyId, int hashAlg, byte[] bMessage) throws TacException{
        return api.signHash(keyId, hashAlg, bMessage);
    }

    public void verifySignature(String keyId, int hashAlg, byte[] signature, byte[] bMessage){
        try {
            this.api.verifySignature(keyId, hashAlg, signature, bMessage);
        } catch (TacException e) {
            if (e.getErrorNumber() == 1037){
                System.out.println("Assinatura invalida");
            }else{
                System.out.println("Erro ao verificar assinatura ");
            }
        }
    }

    public static void CreateKey(Dinamo api, String id, int type) throws TacException{
        api.createKey(id, type);
    }

    public static void CreateKey(Dinamo api, String id, int type, int opc_arg) throws TacException{
        api.createKey(id, type, opc_arg);
    }

    public static byte[] GetPublicKey(Dinamo api, String id) throws TacException{
        byte[] publicKey = api.exportKey(id, TacNDJavaLib.PUBLICKEY_BLOB);
        return publicKey;
    }
}