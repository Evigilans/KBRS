package com.bsu.kbrs.client;

import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAGenerator;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.serpent.ByteDecryptor;
import com.bsu.kbrs.utils.MessageUtils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import org.apache.commons.codec.binary.Base64;

public class Client {

    private static final String NEW_KEYS_PARAM = "--new-keys";
    private static final String PUBLIC_KEY_FILE_NAME = "public";
    private static final String PRIVATE_KEY_FILE_NAME = "private";

    private static String USAGE = "Client options: \n" +
            NEW_KEYS_PARAM + " - generates a new pair of rsa keys\n" +
            "usage:\n" +
            "java -jar client.jar [HOSTNAME][:PORT]\n" +
            "defaults:\n" +
            "HOSTNAME - localhost\n" +
            "PORT - 9090";

    private static RSAKey privateKey;
    private static RSAKey publicKey;

    private static String hostname;
    private static String port;

    private static Path getRsaKeyDirectory() {
        return Paths.get(System.getProperty("user.home"), ".rsa_keys_secret");
    }

    private static void generateNewKeys() {
        RSAGenerator rsaGenerator = new RSAGenerator();
        rsaGenerator.generate(512);

        Path rsaDirectory = getRsaKeyDirectory();
        if (!Files.exists(rsaDirectory)) {
            try {
                Files.createDirectories(rsaDirectory);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        Path privateFile = Paths.get(rsaDirectory.toString(), PRIVATE_KEY_FILE_NAME);
        try {
            Files.write(privateFile,
                    Collections.singletonList(rsaGenerator.getPrivateKey().toString()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Path publicFile = Paths.get(rsaDirectory.toString(), PUBLIC_KEY_FILE_NAME);
        try {
            Files.write(publicFile,
                    Collections.singletonList(rsaGenerator.getPublicKey().toString()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        privateKey = rsaGenerator.getPrivateKey();
        publicKey = rsaGenerator.getPublicKey();

        System.out.println("new keys generated");
    }

    private static boolean readUpKeys() {
        Path rsaDirectory = getRsaKeyDirectory();
        Path privateFile = Paths.get(rsaDirectory.toString(), PRIVATE_KEY_FILE_NAME);
        Path publicFile = Paths.get(rsaDirectory.toString(), PUBLIC_KEY_FILE_NAME);

        try {
            String privateKeyString = new String(Files.readAllBytes(privateFile));
            String publicKeyString = new String(Files.readAllBytes(publicFile));

            privateKey = RSAKey.fromString(privateKeyString);
            publicKey = RSAKey.fromString(publicKeyString);
        } catch (IOException e) {
            // ignore exception
        }

        return privateKey != null && publicKey != null;
    }

    private static Map<String, Object> sendRequest(final Map<String, Object> payload) {
        DataOutputStream outputStream = null;
        DataInputStream dataInputStream = null;
        Socket socket = null;
        try {
            socket = new Socket(hostname, Integer.parseInt(port));
            socket.setSoTimeout(5000);
            outputStream = new DataOutputStream(socket.getOutputStream());
            MessageUtils.sendMessage(outputStream, payload);

            dataInputStream = new DataInputStream(socket.getInputStream());
            return MessageUtils.readMessage(dataInputStream);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (outputStream != null) {
                    outputStream.close();
                }
                if (dataInputStream != null) {
                    dataInputStream.close();
                }
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return null;
    }

    private static Map<String, Object> createAuthRequestPayload(final String login, final String password) {
        Map<String, Object> request = new HashMap<>();
        request.put("type", "auth");
        request.put("rsa-key", publicKey.toString());
        request.put("user", login);
        request.put("password", password);

        return request;
    }

    private static Map<String, Object> createGetFilePayload(final String file, final String sessionId) {
        Map<String, Object> request = new HashMap<>();
        request.put("type", "getFile");
        request.put("fileName", file);
        request.put("sessionId", sessionId);

        return request;
    }

    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("--help") || args[0].equals("-h"))) {
            System.out.println(USAGE);
        }

        boolean isNewKeyPram = false;
        String hostNamePort = "localhost:9090";
        if (args.length > 0) {
            if (args[0].equals(NEW_KEYS_PARAM)) {
                isNewKeyPram = true;
                if (args.length > 1) {
                    hostNamePort = args[1];
                }
            } else {
                hostNamePort = args[0];
            }

            if (args[args.length - 1].equals(NEW_KEYS_PARAM)) {
                isNewKeyPram = true;
            }
        }
        if (hostNamePort.contains(":")) {
            String[] pair = hostNamePort.split(":");
            hostname = pair[0];
            port = pair[1];
        } else {
            hostname = hostNamePort;
            port = "9090";
        }


        if (!readUpKeys() || isNewKeyPram) {
            generateNewKeys();
        }

        String login = null;
        String password = null;

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Login:");
            while (login == null) {
                login = scanner.next();
            }
            System.out.println("Pass:");
            while (password == null) {
                password = scanner.next();
            }

            Map<String, Object> helloPayload = createAuthRequestPayload(login, password);
            Map<String, Object> response = sendRequest(helloPayload);

            if (response != null) {
                final String status = (String) response.get("status");


                if (status != null && status.equals("OK")) {
                    final String encryptedKey = (String) response.get("encryption_key");

                    final String decryptedKey = new RSAEncryption(publicKey, privateKey).decrypt(new BigInteger(encryptedKey));
                    System.out.println(decryptedKey);

                    final String sessionId = login + "/" + encryptedKey.substring(0, 16);
                    System.out.println("Please enter fileName.");
                    while (true) {
                        String requestedFile = scanner.next();
                        System.out.println("Requesting file " + requestedFile);
                        Map<String, Object> getFilePayload = createGetFilePayload(requestedFile, sessionId);
                        Map<String, Object> getFileResponse = sendRequest(getFilePayload);
                        System.out.println(MessageUtils.getGson().toJson(getFileResponse));
                        byte[] fileEncryptedContent = Base64.decodeBase64(((String)getFileResponse.get("content")).getBytes());
                        System.out.println(new ByteDecryptor().decryptBytes(fileEncryptedContent, decryptedKey));
                    }
                } else {
                    String failureReason = (String) response.get("failureReason");
                    if (failureReason != null) {
                        System.out.println("ERROR: " + failureReason);
                    } else {
                        System.out.println("Unrecognized ERROR!");
                    }
                }
            } else {
                System.out.println("Unrecognized ERROR!");
            }
        }
    }

}