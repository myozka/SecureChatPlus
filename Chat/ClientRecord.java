//  ClientRecord.java
package Chat;

// Java
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

// You may need to expand this class for anonymity and revocation control.
public class ClientRecord {

    Socket _socket = null;
    ObjectOutputStream _oos = null;

    public ClientRecord(Socket socket,ObjectOutputStream oos) {
        _socket = socket;
        _oos = oos;
    }

    public Socket getClientSocket() {
        return _socket;
    }

    public ObjectOutputStream getObjectOutputStream() {
        return _oos;
    }
}
