//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
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
import java.security.cert.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;

public class ChatServerThread extends Thread {

    private Socket _socket = null;
    private ChatServer _server = null;
    private Hashtable _records = null;
    
    public static String encode(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return DatatypeConverter.printHexBinary(sha256_HMAC.doFinal(data.getBytes()));
    }

    public ChatServerThread(ChatServer server, Socket socket) {

        super("ChatServerThread");
        _server = server;
        _socket = socket;
        _records = server.getClientRecords();
    }

    public void run() {

        try {

            ObjectOutputStream oos = new ObjectOutputStream(_socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(_socket.getInputStream());

            //round 1
            X509Certificate clientCert = (X509Certificate)ois.readObject();

            FileInputStream fis = new FileInputStream("ca.cer");

            BufferedInputStream bis = new BufferedInputStream(fis);


            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            X509Certificate caCert = (X509Certificate)cf.generateCertificate(bis);
            
            try {
                clientCert.verify(caCert.getPublicKey());
            } catch(Exception e){
                _socket.close();
                return;
            }


            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("asd".toCharArray());

            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            FileInputStream fis2 = new FileInputStream("server.jks");
            clientKeyStore.load(fis2,"asd".toCharArray());

            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry)clientKeyStore.getEntry("server",protParam);
            X509Certificate serverCert = (X509Certificate)privKeyEntry.getCertificate();
            PrivateKey sPrivateKey = privKeyEntry.getPrivateKey();

            PublicKey cPubKey = clientCert.getPublicKey(); // client public key

            //round 2
            oos.writeObject(serverCert);

            String _N_1 = Tools.generateNonce();
            String N_1 = Tools.encryptRSA(cPubKey,_N_1);

            oos.writeObject(N_1);

            //round 3
            String inN_1 = (String) ois.readObject();
            String inN_2 = (String) ois.readObject();
            String inid_room = (String) ois.readObject();

            inN_1 = Tools.decryptRSA(sPrivateKey,inN_1);
            if(!inN_1.equals(_N_1)){
                _socket.close();
                return;
            }
            inN_2 = Tools.decryptRSA(sPrivateKey,inN_2);
            inid_room = Tools.decryptRSA(sPrivateKey,inid_room);
            
            //round 4

            System.out.println(DatatypeConverter.printHexBinary(_server.getRoomA().getEncoded()));

            String resproomKey="";
            if(inid_room.equals("To be"))
                resproomKey = Tools.encryptRSA(cPubKey,DatatypeConverter.printHexBinary(_server.getRoomA().getEncoded()));
            else
                resproomKey = Tools.encryptRSA(cPubKey,DatatypeConverter.printHexBinary(_server.getRoomB().getEncoded()));

            String resp_N_2 = Tools.encryptRSA(cPubKey,inN_2);

            oos.writeObject(resp_N_2);
            oos.writeObject(resproomKey);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                    _socket.getInputStream()));

            Object receivedObj;


            while ((receivedObj = ois.readObject()) != null) {

                Enumeration theClients = _records.elements();

                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();


                    Socket socket = c.getClientSocket();

                    ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                    out.writeObject(receivedObj);

                }
            }
            /*
            while ((receivedMsg = in.readLine()) != null) {

                Enumeration theClients = _records.elements();

                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();


                    Socket socket = c.getClientSocket();

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    out.println(receivedMsg);

                }
            }
            */
            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (Exception e) {

            e.printStackTrace();
        }
        System.out.println("kapandi");
    }
}
