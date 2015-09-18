//
//  CertificateAuthorityThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package Chat;

// socket
import java.net.*;
import java.io.*;

// Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class CertificateAuthorityThread extends Thread {

    private CertificateAuthority _ca;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;

    public CertificateAuthorityThread(CertificateAuthority ca) {

        super("CertificateAuthorityThread");
        _ca = ca;
        _portNum = ca.getPortNumber();
        _outputArea = ca.getOutputArea();
        _serverSocket = null;

        try {

            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {
            _hostName = "0.0.0.0";
        }
    }

    
    //  Accept connections and service them one at a time
    public void run() {

        try {

            _serverSocket = new ServerSocket(_portNum);

            _outputArea.append("CA waiting on " + _hostName + " port " + _portNum + "\n");

            while (true) {

                Socket socket = _serverSocket.accept();

                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

                CertRequest cr = (CertRequest)ois.readObject();

                _outputArea.append("Received request for "+cr.username);

                Boolean result = _ca.addUsername(cr.username);

                if(!result){
                    oos.writeObject(new Boolean(false));
                    oos.writeObject("Username is already taken!");
                }
                else {
                    X509Certificate cert = X509CertificateGenerator.generateCertificate(
                        "CN="+cr.username,cr.pubKey,
                        "CN=SecureChat",_ca.getPrivateKey(),
                        "SHA256withRSA",true,true);
                    _outputArea.append("Issuing certificate.\n");
                    oos.writeObject(new Boolean(true));
                    oos.writeObject(cert);
                }
            }
        } catch (Exception e) {
            System.out.println("CA thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
}
