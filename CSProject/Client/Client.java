package CSProject.Client;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Client {
    private static Socket s = null;
    private static DataOutputStream out = null;
    private static BufferedReader in = null;
    static BufferedInputStream serverIn = null;
    private static DataInputStream sin = null;
    private boolean isValidUser = false;

    public static SecretKey getSymKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        keygenerator.init(256, securerandom);
        SecretKey symmetric_key = keygenerator.generateKey();
        return symmetric_key;
    }

    public static PublicKey readBankPublicKey() {
        PublicKey pub = null;
        try {

            Path path = Paths.get("public_key.pub");
            byte[] bytes = Files.readAllBytes(path);

            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return pub;
    }

    public static byte[] symKeyEnc(SecretKey symmetricKey, PublicKey publicKey) {
        byte[] bytes = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            bytes = cipher.wrap(symmetricKey);
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bytes;
    }

    public static byte[] encID_Pass(String id_pass, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(id_pass.getBytes());
    }

    public Client(String address, int port) throws Exception {

        try {
            s = new Socket(address, port);
            System.out.println("Connected to Server!!");
            in = new BufferedReader(new InputStreamReader(System.in));
            out = new DataOutputStream(s.getOutputStream());
            serverIn = new BufferedInputStream(s.getInputStream());
            sin = new DataInputStream(serverIn);

        } catch (UnknownHostException e) {
            System.out.println(e.getMessage());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        String line = "", clientID = "", clientPassword = "";
        while (!line.equals("2")) {
            try {
                while (!isValidUser) {
                    System.out.println("Enter client ID: ");
                    clientID = in.readLine();
                    System.out.println("Enter client Password: ");
                    clientPassword = in.readLine();
                    String id_pass = clientID.trim() + " " + clientPassword.trim();
                    SecretKey symmetricKey = getSymKey();
                    byte[] symmetricEncryptionBytes = encID_Pass(id_pass, symmetricKey);
                    byte[] asymmetricCipher = symKeyEnc(symmetricKey, readBankPublicKey());
                    out.writeInt(asymmetricCipher.length);
                    out.write(asymmetricCipher);
                    out.writeInt(symmetricEncryptionBytes.length);
                    out.write(symmetricEncryptionBytes);

                    isValidUser = sin.readBoolean();
                    if (!isValidUser)
                        System.out.println("Invalid ID or Password !!! \nPlease enter correct credentials !!!\n");
                }

                while (true) {
                    int balance = sin.readInt();
                    System.out.println(
                            "Your account balance is " + balance + ". \nSelect one of the following options:");
                    System.out.println("1.Transfer");
                    System.out.println("2.Exit");
                    line = in.readLine();
                    out.writeUTF(line);
                    if (line.compareTo("2") == 0) {
                        break;
                    }
                    System.out.println("Enter the receiver's ID:");
                    String get_id = in.readLine();
                    System.out.println("Enter the amount:");
                    String get_amount = in.readLine();
                    String send = get_id + " " + get_amount;
                    out.writeUTF(send);
                    int get_result = sin.readInt();
                    if (get_result == 0) {
                        System.out.println("Your transaction was unsuccessful.");
                    } else {
                        System.out.println("Your transaction was successful.");
                    }

                }
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
        System.out.println("Exiting Client!!");
        try {
            in.close();
            out.close();
            s.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {

        // String host = "remote.cs.binghamton.edu";
        String host = args[0];
        // int port = 6996;
        int port = Integer.parseInt( args[1] );
        Client client = new Client(host, port);
    }
}
