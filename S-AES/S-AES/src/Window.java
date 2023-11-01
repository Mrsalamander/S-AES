
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class Window extends JFrame implements ActionListener {
    JTextField textPlain,textKey,textCipher,textA;//视图
    JTextArea showArea;//视图
    JButton EncryptButton;//控制器
    JButton BruteForceButton;//控制器
    JRadioButton radioButton;
    Window () {
        init();
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    void init () {
        textPlain = new JTextField(16);
        textKey = new JTextField(16);
        textCipher = new JTextField(16);
        showArea = new JTextArea();
        EncryptButton = new JButton("Encrypt/Decrypt");
        BruteForceButton = new JButton("Brute Force Attack");
        radioButton = new JRadioButton("Radio");
        JPanel pNorth = new JPanel();
        pNorth.add(new JLabel("Plaintext"));
        pNorth.add(textPlain);
        pNorth.add(new JLabel("Ciphertext"));
        pNorth.add(textCipher);
        pNorth.add(new JLabel("Key"));
        pNorth.add(textKey);
        pNorth.add(EncryptButton);
//        pNorth.add(BruteForceButton);
//        pNorth.add(radioButton);
        EncryptButton.addActionListener(this);
//        BruteForceButton.addActionListener(this);
        add(pNorth,BorderLayout.NORTH);
        add(new JScrollPane(showArea), BorderLayout.CENTER);
        showArea.append("           Welcome to use the S-AES algorithm !  The plaintext/ciphertext input box can enter an 16-bit binary string or 2 character or less.The key"+"\n"+"input box's key should be 16-bit/32-bit binary string.");
        showArea.append("\n");
    }
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == EncryptButton) {
            try {
                String plainText = textPlain.getText();
                String keyText = textKey.getText();
                String cipherText = textCipher.getText();
                if ((!cipherText.isEmpty()) && (plainText.isEmpty()) && (!keyText.isEmpty())) {
                    methodD(cipherText, keyText);
                }
                else if ((cipherText.isEmpty()) && (!plainText.isEmpty()) && (!keyText.isEmpty())) {
                    methodE(plainText, keyText);
                }
                else if ((!cipherText.isEmpty()) && (!plainText.isEmpty()) && (keyText.isEmpty())) {
                    showArea.append("Error!: If you want to encrypt or decrypt, delete one of the plaintext or ciphertext; "
                            + "\n" +
                            "           If you want to brute force, click the Brute Force button."+ "\n");
                }
                else if ((!cipherText.isEmpty()) && (!plainText.isEmpty()) && (!keyText.isEmpty())) {
                    showArea.append("Error!: Check your input."+ "\n");
                }
                else {
                    showArea.append("Error!: The plaintext or the ciphertext is empty"+ "\n");
                }
                //判定输入内容是否为空，来决定采用的的方法
            } catch (Exception ex) {
                showArea.append("Error!: Please check the input format." + "\n" + ex + "\n");
            }
        } else if (e.getSource() == BruteForceButton) {
            try {
                String plainText = textPlain.getText();
                String cipherText = textCipher.getText();
                String keyText = textKey.getText();
                if ((!cipherText.isEmpty()) && (!plainText.isEmpty()) && (keyText.isEmpty())) {
//                    methodBF(plainText, cipherText);
                    showArea.append("Error!BF not available");
                }
            }
            catch (Exception ex) {
                showArea.append("Error!" + "\n" + ex + "\n");
            }
        }
    }
    public void methodE(String strP, String strK ){
        String p = strP;
        String key = strK;
        AESEncryptCreator dir = new AESEncryptCreator(p,key);
        String c = dir.encrypt();
        showArea.append("Encrypted:"+"\n");
        showArea.append("Plaintext :" + p + "   " + "Key :" + key + "\n");
        showArea.append("Ciphertext:");
        showArea.append(c+"\n");
    }
    public void methodD(String strC, String strK ){
        String c = strC;
        String key = strK;
        AESDecryptCreator dir = new AESDecryptCreator(c, key);
        String newp = dir.decrypt();
        showArea.append("Decrypted:"+"\n");
        showArea.append("Ciphertext :" + c + "   " + "Key :" + key + "\n");
        showArea.append("Plaintext:");
        showArea.append(newp+"\n");
    }
//    public void methodBF(String strP,String strC) {
//        String p = strP;
//        String c = strC;
//        long timestamp1 = System.currentTimeMillis();
//        String keys = f.run(p,c);
//        long timestamp2 = System.currentTimeMillis();
//        String elapsedTime = String.valueOf(timestamp2 - timestamp1);
//        showArea.append("Elapsed time : "+elapsedTime+"ms"+"\n");
//        String key = f.find();
//        showArea.append(keys);
//        showArea.append("\n");
//        showArea.append(key);
//        showArea.append("\n");
//    }
}
