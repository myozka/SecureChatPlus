/**
 *  Created 2/16/2003 by Ting Zhang 
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package Chat;

// socket
import java.net.*;
import java.io.*;

//  Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;
    private String _roomKey;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _roomKey = "yoloswagger";
        _outputArea = client.getOutputArea();
    }

    public void run() {

        try {

            oos = new ObjectOutputStream(_socket.getOutputStream());
            ois = new ObjectInputStream(_socket.getInputStream());

            PrivateKey mPrivateKey = _client.getPrivateKey();
            X509Certificate clientCert = (X509Certificate)_client.getCertificate();

            //round 1
            oos.writeObject(clientCert);

            //round 2
            X509Certificate serverCert = (X509Certificate)ois.readObject();
            String N_1 = (String)ois.readObject();

            String _N_1 = Tools.decryptRSA(mPrivateKey,N_1);


            PublicKey sPubKey = serverCert.getPublicKey();
            
            FileInputStream fis = new FileInputStream("ca.cer");
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate)cf.generateCertificate(bis);
            
            try {
                serverCert.verify(caCert.getPublicKey());
            } catch(Exception e){
                _socket.close();
                return;
            }

            String resp_N_1 = Tools.encryptRSA(sPubKey,_N_1);
            String _N_2 = Tools.generateNonce();
            String resp_N_2 = Tools.encryptRSA(sPubKey,_N_2);
            String resp_id_room = Tools.encryptRSA(sPubKey,_client.getRoomName());
            
            //round 3
            oos.writeObject(resp_N_1);
            oos.writeObject(resp_N_2);
            oos.writeObject(resp_id_room);

            //round 4
            String N_2 = (String)ois.readObject();
            String roomKey= (String)ois.readObject();

            N_2 = Tools.decryptRSA(mPrivateKey,N_2);
            if(!N_2.equals(_N_2)){
                _socket.close();
                return;
            }

            _roomKey = Tools.decryptRSA(mPrivateKey,roomKey);

            Integer seq = -1;
            String msg;

            while ((msg = (String)ois.readObject()) != null) {

                String mac = (String)ois.readObject();
                String calculatedMac = Tools.hmac(_roomKey,msg);
                if(!calculatedMac.equals(mac)){
                    System.out.println("MACs doesn't match");
                    continue;
                }

                msg = Tools.decryptAES(_roomKey,msg);
                byte [] msgbytes=DatatypeConverter.parseHexBinary(msg);
                ByteArrayInputStream bais = new ByteArrayInputStream(msgbytes);
                ObjectInputStream oin = new ObjectInputStream(bais);
                MessageBlock currentBlock = (MessageBlock)oin.readObject();
                if(currentBlock.sequenceNo < seq)
                    continue;
                seq = currentBlock.sequenceNo;
                _outputArea.append(currentBlock.username+ "> "+currentBlock.message);
            }

            _socket.close();

        } catch (Exception e) {

            e.printStackTrace();
        }

    }

    public void sendMessage(String msg){

        MessageBlock halfBlock = new MessageBlock("",msg,(int)System.currentTimeMillis()/1000,0);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(halfBlock);
            String str = DatatypeConverter.printHexBinary(bos.toByteArray());
            str = Tools.encryptAES(_roomKey,str);
            String mac = Tools.hmac(_roomKey,str);
            oos.writeObject(str);
            oos.writeObject(mac);
        } catch(Exception ex) {
            return;
        }

    }

    public void consumeMessage(String msg) {


        if (msg != null) {
            _outputArea.append(msg);
        }

    }
}
