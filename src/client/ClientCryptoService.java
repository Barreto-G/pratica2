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