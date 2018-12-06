package com.bsu.kbrs.server;

import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.serpent.FileEncryptor;
import com.bsu.kbrs.utils.ApplicationUtils;
import com.bsu.kbrs.utils.MessageUtils;
import org.apache.commons.codec.binary.Base64;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class Server {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(9090);
            while (true) {
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());

                Map<String, Object> message = MessageUtils.readMessage(inputStream);
                Map<String, Object> response = new HashMap<>();

                String type = (String) message.get("type");
                System.out.println(type);
                if (type.equals("auth")) {
                    response = loginUser(message);
                }
                if (type.equals("getFile")) {
                    response = returnFile(message);
                }

                System.out.println(response);
                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                MessageUtils.sendMessage(outputStream, response);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, Object> loginUser(Map<String, Object> message) {
        String user = (String) message.get("user");
        String password = (String) message.get("password");
        String rsaKey = (String) message.get("rsa-key");

        Map<String, Object> response = new HashMap<>();
        response.put("type", "auth");
        if (authenticate(user, password)) {
            RSAEncryption rsaEncryption = new RSAEncryption();
            rsaEncryption.setPublicKey(RSAKey.fromString(rsaKey));

            String secureKey = ApplicationUtils.generateRandomKey(32);
            String enrypted = rsaEncryption.encrypt(secureKey).toString();

            response.put("status", "OK");
            response.put("encryption_key", enrypted);

            Map<String, Object> updateData = new HashMap<>();
            updateData.put("password", password);
            updateData.put("secureKey", secureKey);
            updateData.put("sessionId", user + "/" + enrypted.substring(0, 16));

            writeUserSystemData(user, updateData);
        } else {
            response.put("status", "FAIL");
            response.put("failureReason", "user or password is not valid");
        }

        return response;
    }

    private static Map<String, Object> returnFile(Map<String, Object> message) {
        String sessionId = (String) message.get("sessionId");

        String userName = sessionId.split("/")[0];
        String fileName = "files/" + userName + "/" + message.get("fileName");

        Map<String, Object> response = new HashMap<>();
        if (compareSessionId(userName, sessionId)) {
            String secureKey = readSecureKey(userName);
            byte[] encryptedFile = encryptRequestedFileFile(fileName, secureKey);

            response.put("status", "OK");
            response.put("content", new String(Base64.encodeBase64(encryptedFile)));
        } else {
            response.put("status", "FAIL");
            response.put("failureReason", "File not found");
        }

        return response;
    }

    private static byte[] encryptRequestedFileFile(String fileName, String secureKey) {
        FileEncryptor fileEncryptor = new FileEncryptor();
        return fileEncryptor.encryptFile(fileName, secureKey);
    }

    private static String readSecureKey(String user) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            return (String) map.get("secureKey");
        }
        return null;
    }

    private static boolean compareSessionId(String user, String sessionId) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            String fileSessionId = (String) map.get("sessionId");
            return fileSessionId != null && fileSessionId.equals(sessionId);
        }
        return false;
    }

    private static boolean authenticate(String user, String password) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            String filePassword = (String) map.get("password");
            return filePassword != null && filePassword.equals(password);
        }
        return false;
    }

    private static Map<String, Object> readUserSystemData(String user) {
        try {
            byte[] file = Files.readAllBytes(Paths.get("files/" + user + "/system_info/_info"));
            Map<String, Object> map = new HashMap<>();
            map = MessageUtils.getGson().fromJson(new String(file), map.getClass());
            return map;
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    private static void writeUserSystemData(String user, Map<String, Object> data) {
        try {
            String jsonData = MessageUtils.getGson().toJson(data, data.getClass());
            Files.write(Paths.get("files/" + user + "/system_info/_info"), jsonData.getBytes());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
