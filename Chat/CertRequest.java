
package Chat;

import java.io.Serializable;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class CertRequest implements Serializable {
	String username;
	PublicKey pubKey;
	byte[] signature;

	CertRequest(String username,PublicKey pubKey,byte[] signature){
		this.username = username;
		this.pubKey = pubKey;
		this.signature = signature;
	}
}