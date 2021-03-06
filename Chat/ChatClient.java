//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.
package Chat;

//  AWT/Swing
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

//  Java
import java.io.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.net.*;



//  Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;

public class ChatClient {

    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;
    String _loginName;
    String _roomName;
    ChatServer _server;
    ChatClientThread _thread;
    ChatLoginPanel _loginPanel;
    ChatRoomPanel _chatPanel;
    PrintWriter _out = null;
    BufferedReader _in = null;
    CardLayout _layout;
    JFrame _appFrame;

    Socket _socket = null;
    SecureRandom secureRandom;
    KeyStore clientKeyStore;
    X509Certificate _certificate;
    PrivateKey _privateKey;
    
    //  ChatClient Constructor
    //
    //  empty, as you can see.
    public ChatClient() {

        _loginName = null;
        _server = null;

        try {
            initComponents();
        } catch (Exception e) {
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "Login");

    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);
    }

    //  main
    //
    //  Construct the app inside a frame, in the center of the screen
    public static void main(String[] args) {
        
        ChatClient app = new ChatClient();

        app.run();
    }

    //  initComponents
    //
    //  Component initialization
    private void initComponents() throws Exception {

        _appFrame = new JFrame("SecureChat+");
        _layout = new CardLayout();
        _appFrame.getContentPane().setLayout(_layout);
        _loginPanel = new ChatLoginPanel(this);
        _chatPanel = new ChatRoomPanel(this);
        _appFrame.getContentPane().add(_loginPanel, "Login");
        _appFrame.getContentPane().add(_chatPanel, "ChatRoom");
        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownOutput();
            _socket.close();

        } catch (Exception err) {
            System.out.println("ChatClient error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  connect
    //
    //  Called from the login panel when the user clicks the "connect"
    //  button. You will need to modify this method to add certificate
    //  authentication.  
    //  There are two passwords : the keystorepassword is the password
    //  to access your private key on the file system
    //  The other is your authentication password on the CA.
    //
    public PrivateKey getPrivateKey(){
        return _privateKey;
    }

    public X509Certificate getCertificate(){
        return _certificate;
    }

    public String getRoomName(){
        return _roomName;
    }

    public int connect(String loginName,String roomName,String keyStoreName, char[] keyStorePassword,
            String caHost, int caPort,
            String serverHost, int serverPort) {

        try {

            _loginName = loginName;
            _roomName = roomName;

            clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(null,keyStorePassword);

            //  Read the client keystore
            //         (for its private/public keys)
            //  Establish secure connection to the CA
            //  Send public key and get back certificate
            //  Use certificate to establish secure connection with server
            //
            //
            try{
                FileInputStream fis = new FileInputStream(keyStoreName);
                clientKeyStore.load(fis,keyStorePassword);
            } catch(Exception e){

            }

            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyStorePassword);

            if(!clientKeyStore.containsAlias(loginName)){
                System.out.println("No certificate found.");
                Socket certSocket = null;
                // get cert here
                try{
                    certSocket = new Socket(caHost,caPort);
                } catch(Exception e){
                    System.out.println("Couldn't connect to Certificate Authority!");
                    return ERROR;
                }

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();

                ObjectOutputStream oos = new ObjectOutputStream(certSocket.getOutputStream());
                
                Signature signature=Signature.getInstance("SHA256withRSA");
                signature.initSign(kp.getPrivate());
                signature.update(kp.getPublic().getEncoded());
                byte[] signatureBytes=signature.sign();
                
                oos.writeObject(new CertRequest(loginName,kp.getPublic(),signatureBytes));

                ObjectInputStream ois = new ObjectInputStream(certSocket.getInputStream());
                Boolean success = (Boolean)ois.readObject();
                if(success){
                    X509Certificate cert = (X509Certificate)ois.readObject();
                    System.out.println(cert);
                    KeyStore.PrivateKeyEntry pke = 
                        new KeyStore.PrivateKeyEntry(kp.getPrivate(),
                            new java.security.cert.Certificate[]{cert});
                    clientKeyStore.setEntry(loginName,pke,protParam);
                    clientKeyStore.store(new FileOutputStream(keyStoreName),keyStorePassword);
                } else {
                    String error = (String)ois.readObject();
                    System.out.println(error);
                    return ERROR;
                }
            }

            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry)clientKeyStore.getEntry(loginName,protParam);
            _certificate = (X509Certificate)privKeyEntry.getCertificate();
            _privateKey = privKeyEntry.getPrivateKey();

            // Server Connection after getting certificate

            _socket = new Socket(serverHost, serverPort);
            _out = new PrintWriter(_socket.getOutputStream(), true);

            
            _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));

            _layout.show(_appFrame.getContentPane(), "ChatRoom");

            _thread = new ChatClientThread(this);
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println("Don't know about the serverHost: " + serverHost);
            System.exit(1);

        } catch (IOException e) {

            System.err.println("Couldn't get I/O for "
                    + "the connection to the serverHost: " + serverHost);
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();

            System.exit(1);

        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

        return ERROR;

    }

    //  sendMessage
    //
    //  Called from the ChatPanel when the user types a carrige return.
    public void sendMessage(String msg) {

        _thread.sendMessage(msg);

    }

    public Socket getSocket() {

        return _socket;
    }

    public JTextArea getOutputArea() {

        return _chatPanel.getOutputArea();
    }
}
