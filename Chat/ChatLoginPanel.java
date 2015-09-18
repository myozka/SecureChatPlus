//  ChatLoginPanel.java
//
//  Last modified 1/30/2000 by Alan Frindell
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  GUI class for the login panel.
//
//  You should not have to modify this class.
package Chat;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class ChatLoginPanel extends JPanel {

    JTextField _loginNameField;
    JComboBox _roomField;
    JTextField _serverHostField;
    JTextField _serverPortField;
    JTextField _caHostField;
    JTextField _caPortField;
    JTextField _keyStoreNameField;
    JPasswordField _keyStorePasswordField;
    JLabel _errorLabel;
    JButton _connectButton;
    ChatClient _client;

    public ChatLoginPanel(ChatClient client) {
        _client = client;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("ChatLoginPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        JLabel label;

        setLayout(gridBag);

        addLabel(gridBag, "Welcome to SecureChat+", SwingConstants.CENTER,
                1, 0, 2, 1);
        addLabel(gridBag, "Username: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "Room: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "KeyStore File Name: ", SwingConstants.LEFT, 1, 3, 1, 1);
        addLabel(gridBag, "KeyStore Password: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Server Host Name: ", SwingConstants.LEFT, 1, 5, 1, 1);
        addLabel(gridBag, "Server Port: ", SwingConstants.LEFT, 1, 6, 1, 1);
        addLabel(gridBag, "CA Host Name: ", SwingConstants.LEFT, 1, 7, 1, 1);
        addLabel(gridBag, "CA Port: ", SwingConstants.LEFT, 1, 8, 1, 1);

        _loginNameField = new JTextField();
        addField(gridBag, _loginNameField, 2, 1, 1, 1);

        String[] rooms = {"To be","Not to be"};
        _roomField = new JComboBox(rooms);
        _roomField.setSelectedIndex(0);
        addField(gridBag,_roomField,2,2,1,1);

        _keyStoreNameField = new JTextField();
        addField(gridBag, _keyStoreNameField, 2, 3, 1, 1);
        _keyStorePasswordField = new JPasswordField();
        _keyStorePasswordField.setEchoChar('*');
        addField(gridBag, _keyStorePasswordField, 2, 4, 1, 1);

        _serverHostField = new JTextField();
        addField(gridBag, _serverHostField, 2, 5, 1, 1);
        _serverPortField = new JTextField();
        addField(gridBag, _serverPortField, 2, 6, 1, 1);

        _caHostField = new JTextField();
        addField(gridBag, _caHostField, 2, 7, 1, 1);
        _caPortField = new JTextField();
        addField(gridBag, _caPortField, 2, 8, 1, 1);

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER,
                1, 9, 2, 1);

        // just for testing purpose

        _loginNameField.setText("cs470");
        _keyStoreNameField.setText("client1");
        _keyStorePasswordField.setText("123456");
        _caHostField.setText("localhost");
        _caPortField.setText("6666");
        _serverHostField.setText("localhost");
        _serverPortField.setText("7777");

        _errorLabel.setForeground(Color.red);

        _connectButton = new JButton("Connect");
        c.gridx = 1;
        c.gridy = 10;
        c.gridwidth = 2;
        gridBag.setConstraints(_connectButton, c);
        add(_connectButton);

        _connectButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                connect();
            }
        });
    }

    JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
            int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.anchor = GridBagConstraints.WEST;
        } else {
            c.insets = new Insets(5, 0, 5, 0);
        }
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    void addField(GridBagLayout gridBag, JComponent field, int x, int y,
            int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96,
                field.getMinimumSize().height));
        c.insets = new Insets(5, 0, 5, 0);
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(field, c);
        add(field);
    }

    private void connect() {

        int serverPort;
        int caPort;

        String loginName = _loginNameField.getText();

        String keyStoreName = _keyStoreNameField.getText();
        String roomName = (String)_roomField.getSelectedItem();
        char[] keyStorePassword = _keyStorePasswordField.getPassword();

        String serverHost = _serverHostField.getText();
        String caHost = _caHostField.getText();

        if (loginName.equals("")
                || keyStoreName.equals("")
                || keyStorePassword.length == 0
                || serverHost.equals("")
                || _serverPortField.getText().equals("")
                || caHost.equals("")
                || _caPortField.getText().equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            serverPort = Integer.parseInt(_serverPortField.getText());
            caPort = Integer.parseInt(_caPortField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        System.out.println("We are connecting to ...");

        switch (_client.connect(loginName,
                roomName,
                keyStoreName,
                keyStorePassword,
                caHost,
                caPort,
                serverHost,
                serverPort)) {

            case ChatClient.SUCCESS:
                //  Nothing happens, this panel is now hidden
                _errorLabel.setText(" ");
                break;
            case ChatClient.CONNECTION_REFUSED:
            case ChatClient.BAD_HOST:
                _errorLabel.setText("Connection Refused!");
                break;
            case ChatClient.ERROR:
                _errorLabel.setText("ERROR!  Stop That!");
                break;

        }

        System.out.println("We finished connecting to ...");


    }
}
