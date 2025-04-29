package examples;
import java.util.Base64;
import com.dinamonetworks.Dinamo;
 
import br.com.trueaccess.TacAccessToken;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
 
public class AToken {
    public static void main(String[] args) {
        try {
            String ip = "187.33.9.132";
            String user = "utfpr1";
            String password = "segcomp20241";
 
            //Abre sessão que irá criar o AToken.
            Dinamo dnIssueSession   = new Dinamo();
            dnIssueSession.openSession(ip, user, password, TacNDJavaLib.DEFAULT_PORT,
                    false, false, true);
 
            //Emite o AToken sem tempo de expiração.
            TacAccessToken newAToken = dnIssueSession.issueAToken(TacNDJavaLib.DN_A_TOKEN_INFINITE);
 
            //Lista os ATokens.
            TacAccessToken[] atokenList = dnIssueSession.listAToken();
 
            System.out.println("ATokens List:");
            for(int i=0; i<atokenList.length; i++)
            {
                System.out.println(i + " : " + atokenList[i].getStrUserName());
                System.out.println("    Expiration: " + atokenList[i].getExpiration());
                System.out.println("    Key: " + new String(Base64.getEncoder().encode(atokenList[i].getKey())));
                System.out.println("    atoken: " + new String(Base64.getEncoder().encode(atokenList[i].getAToken())));
                System.out.println("    atoken full: " + new String(Base64.getEncoder().encode(atokenList[i].getFullAToken())));
            }
 
            //Abre sessão utilizando o AToken.
            Dinamo atokenSession = new Dinamo();
            atokenSession.openSession(ip, newAToken, TacNDJavaLib.DEFAULT_PORT,
                    false, false, true);
            //Fecha sessão do AToken.
            atokenSession.closeSession();
 
            //Recupera a quantidade total de tokens do HSM.
            int totalAtokens = dnIssueSession.getATokenCounter();
            System.out.println("Atokens Count: " + totalAtokens);
 
            //Executa o Garbage Collector de Access Tokens do HSM.
            System.out.println("Running AToken GC...");
            dnIssueSession.runATokenGC();
 
            //Utiliza a primeira sessão para revogar o AToken.
            System.out.println("Revoking AToken...");
            dnIssueSession.revokeAToken(newAToken);
 
            //Fecha primeira sessão.
            dnIssueSession.closeSession();
        } catch (TacException e) {
            e.printStackTrace();
        }
    }
}