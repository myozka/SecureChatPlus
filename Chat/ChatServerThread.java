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
    private String _roomKey = null;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;

    public static String encode(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return DatatypeConverter.printHexBinary(sha256_HMAC.doFinal(data.getBytes()));
    }

    public ChatServerThread(ChatServer server, Socket socket, ObjectOutputStream oos) {

        super("ChatServerThread");
        _server = server;
        _socket = socket;
        this.oos = oos;
    }

    public void run() {

        try {
            ois = new ObjectInputStream(_socket.getInputStream());

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
            String clientName = clientCert.getSubjectX500Principal().getName().substring(3);
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

            String resproomKey="";
            if(inid_room.equals("To be"))
                resproomKey = _server.getRoomA();
            else
                resproomKey = _server.getRoomB();
            
            _roomKey = resproomKey;

            resproomKey = Tools.encryptRSA(cPubKey,resproomKey);
            String resp_N_2 = Tools.encryptRSA(cPubKey,inN_2);

            oos.writeObject(resp_N_2);
            oos.writeObject(resproomKey);

            _server.addClient(inid_room,new ClientRecord(_socket,oos));

            String receivedMessageBlockString;


            while ((receivedMessageBlockString = (String)ois.readObject()) != null) {

                //taking input 
                String rmbs = receivedMessageBlockString;
                String macRmbs = (String)ois.readObject();
                //calcualte and comapre MAC
                String calculatedMac = Tools.hmac(_roomKey,rmbs);
                if(!calculatedMac.equals(macRmbs)){
                    System.out.println("MACs doesn't match");
                    continue;
                }
                //Get decrypted messageblock 
                String object = Tools.decryptAES(_roomKey,rmbs);
                ByteArrayInputStream bais = new ByteArrayInputStream(DatatypeConverter.parseHexBinary(object));
                ObjectInputStream str = new ObjectInputStream(bais);
                //edit the content
                MessageBlock mb = (MessageBlock) str.readObject();
                str.close();
                bais.close();
                mb.username = clientName;
                mb.sequenceNo = _server.seqNo;
                mb.timestamp = new Integer((int)System.currentTimeMillis()/1000);
                _server.seqNo++;

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream ostr = null;
                ostr = new ObjectOutputStream(bos);
                ostr.writeObject(mb);
                String toSend = DatatypeConverter.printHexBinary(bos.toByteArray());
                toSend = Tools.encryptAES(_roomKey,toSend);
                String toSendMac = Tools.hmac(_roomKey,toSend);

                Enumeration theClients = _server.getClientRecords(inid_room).elements();

                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();

                    try{
                        ObjectOutputStream out = c.getObjectOutputStream();

                        out.writeObject(toSend);
                        out.writeObject(toSendMac);    
                    } catch(Exception e){
                        continue;
                    }

                }
            }
           
            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (Exception e) {

        }
    }
}
