package CSProject.Server;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

class FileGeneration {
    static String name1 = "alice";
    static String name2 = "bob";
    static String name3 = "tom";
    static String pwd1 = "1234";
    static String pwd2 = "5678";
    static String pwd3 = "9012";
    static String clients[] = { name1, name2, name3 };
    static String passwds[] = { pwd1, pwd2, pwd3 };
    static String balance = "10000";

    public static ArrayList<Clients> createFile() throws Exception {
        ArrayList<Clients> cli = new ArrayList<>();
        FileWriter passwordFile = new FileWriter("passwd.txt");
        FileWriter balanceFile = new FileWriter("balance.txt");

        for (int i = 0; i < clients.length; i++) {
            String pass = createHashedPasswd(passwds[i]);
            cli.add(new Clients(clients[i], 10000, pass));
            passwordFile.write(clients[i]);
            passwordFile.write(" ");
            passwordFile.write(pass);
            passwordFile.write("\n");
            balanceFile.write(clients[i]);
            balanceFile.write(" ");
            balanceFile.write(balance);
            balanceFile.write("\n");
        }
        passwordFile.close();
        balanceFile.close();
        return cli;
    }

    public static void updateValue(String ov, String nv) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("balance.txt"));
        String oc = "";
        String nc = "";
        String line = reader.readLine();
        FileWriter writer = new FileWriter("balance.txt");
        while (line != null) {
            oc = oc + line + System.lineSeparator();
            line = reader.readLine();
        }
        nc = oc.replaceAll(ov, nv);
        writer.write(nc);
        reader.close();
        writer.close();
    }

    public static String createHashedPasswd(String input) {
        try {
            MessageDigest m = MessageDigest.getInstance("SHA-1");
            byte[] md = m.digest(input.getBytes());
            BigInteger num = new BigInteger(1, md);
            String ht = num.toString(16);
            while (ht.length() < 32) 
                ht = "0" + ht;
            
            return ht;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}


class Clients {
    public int balance;
    public String name, hashedPwd;

    Clients(String nameInput, int balanceInput, String hashInput){
        name = nameInput;
        balance = balanceInput;
        hashedPwd = hashInput;
    }

    public double getAmount(){
        return this.balance;
    }

    public void addAmount(int amt){
        this.balance = this.balance + amt;
    }

    public int transferBalance(Clients reciver, int amt) throws Exception{
        if(amt>balance  || amt<0) return 0;
        String prevVal = name + " " + balance;
        balance = balance - amt;
        String newValue = name + " " + balance;
        FileGeneration.updateValue(prevVal,newValue);
        prevVal = reciver.name + " " + reciver.balance;
        reciver.addAmount(amt);
        newValue = reciver.name + " " + reciver.balance;
        FileGeneration.updateValue(prevVal,newValue);
        return 1;
    }
}

public class Server {
    private static ServerSocket ss = null;
    private static Socket s = null;
    private static DataInputStream in = null;
    private static DataOutputStream out = null;
    private static ArrayList<Clients> cli = null;
    private static Clients currentUser = null;

    static File curDir = new File(".");


    public static boolean validate_user(String query) {
        String client_id = query.split(" ")[0];
        String hashedPwd = FileGeneration.createHashedPasswd(query.split(" ")[1]);
        for (Clients var : cli) {
            if (var.name.compareTo(client_id) == 0 && var.hashedPwd.compareTo(hashedPwd) == 0) {
                currentUser = var;
                return true;
            }
        }
        return false;
    }

    public static PrivateKey readPrivateKey() {

        PrivateKey privateKey = null;
        Path path = Paths.get("private_key.key");
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(ks);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }


    public static void generateNewKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            Key pub = kp.getPublic();
            Key pvt = kp.getPrivate();

            String strPrivateFile = "private_key";
            FileOutputStream out = new FileOutputStream(strPrivateFile + ".key");
            out.write(pvt.getEncoded());
            out.close();

            String strPublicFile = "public_key";
            out = new FileOutputStream(strPublicFile + ".pub");
            out.write(pub.getEncoded());
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey symKeyDec(byte[] cipherKey, PrivateKey privateKey) {
        Key result = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            result = cipher.unwrap(cipherKey, "AES", Cipher.SECRET_KEY);
            return (SecretKey) result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decID_Pass(byte[] cipherText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    public Server(int port) throws Exception {
        cli = FileGeneration.createFile();
        ss = new ServerSocket(port);

        try {
            System.out.println("Server Started");
            while (true) {
                
                System.out.println("Waiting for client");
                s = ss.accept();
                System.out.println("Client accepted");
                out = new DataOutputStream(s.getOutputStream());
                BufferedInputStream bin = new BufferedInputStream(s.getInputStream());
                boolean login = false;
                in = new DataInputStream(bin);
                while (true) {
                    int length = in.readInt();
                    byte[] message = new byte[length];
                    in.readFully(message, 0, message.length);

                    int length2 = in.readInt();
                    byte[] message2 = new byte[length2];
                    in.readFully(message2, 0, message2.length);
                    SecretKey skDecription = symKeyDec(message, readPrivateKey());
                    String aesDecription = decID_Pass(message2, skDecription);
                    login = validate_user(aesDecription);
                    out.writeBoolean(login);
                    if (login)
                        break;
                }
                if (login) {
                    while (true) {
                        out.writeInt(currentUser.balance);
                        String input = in.readUTF();
                        if (input.compareTo("2") == 0) {
                            System.out.println("Closing connection ==> "+ currentUser.name);
                            s.close();
                            break;
                        }
                        String accBal = in.readUTF();
                        String account = accBal.split(" ")[0];
                        int amount = 0;

                        int result = 0;
                        boolean flag = true;
                        try {
                            amount = Integer.parseInt(accBal.split(" ")[1]);
                        } catch (NumberFormatException e) {
                            out.writeInt(result);
                            flag = false;
                            System.err.println("enter amount in numbers");
                        }
                        if(flag){
                            Clients clientAcc = null;
                            for (Clients u : cli) {
                                if (u.name.compareTo(account) == 0) {
                                    clientAcc = u;
                                }
                            }
                            if (Objects.isNull(clientAcc)) {
                                out.writeInt(result);
                            } else {
                                result = currentUser.transferBalance(clientAcc, amount);
                                clientAcc = null;
                                out.writeInt(result);
                            }
                        }
                        //
                        // Clients clientAcc = null;
                        // for (Clients var : cli) {
                        //     if (var.name.compareTo(account) == 0) {
                        //         clientAcc = var;
                        //     }
                        // }
                        // int result = 0;
                        // if (Objects.isNull(clientAcc)) {
                        //     System.out.println("null case");
                        //     out.writeInt(result);
                        // } else {
                        //     result = currentUser.transferBalance(clientAcc, amount);
                        //     clientAcc = null;
                        //     out.writeInt(result);
                        // }
                    }
                }

            }

        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) throws Exception {
        // int port = 6996;
        int port = Integer.parseInt( args[0] );
        // generate public private keys
        try {
            generateNewKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Server server = new Server(port);
    }
}