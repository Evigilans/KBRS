package com.bsu.kbrs.server;

import com.bsu.kbrs.constant.FieldConstant;
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

import static com.bsu.kbrs.constant.SystemConfigurationConstant.*;
import static com.bsu.kbrs.constant.FieldConstant.*;

public class Server {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(SOCKET_PORT);
            while (true) {
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());

                Map<String, Object> message = MessageUtils.readMessage(inputStream);
                Map<String, Object> response = new HashMap<>();

                String type = (String) message.get(TYPE);
                System.out.println(type);
                if (type.equals(AUTH)) {
                    response = loginUser(message);
                }
                if (type.equals(GET_FILE)) {
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
        String user = (String) message.get(USER);
        String password = (String) message.get(PASSWORD);

        Map<String, Object> response = new HashMap<>();
        response.put(TYPE, AUTH);
        if (authenticate(user, password)) {
            String rsaKey = findRSAKey(message);

            if (rsaKey != null && !rsaKey.isEmpty()) {
                RSAEncryption rsaEncryption = new RSAEncryption();
                rsaEncryption.setPublicKey(RSAKey.fromString(rsaKey));

                String secureKey = ApplicationUtils.generateRandomKey(SESSION_KEY_LENGTH);
                String enrypted = rsaEncryption.encrypt(secureKey).toString();

                response.put(STATUS, STATUS_OK);
                response.put(ENCRYPTION_KEY, enrypted);

                Map<String, Object> updateData = new HashMap<>();
                updateData.put(PASSWORD, password);
                updateData.put(SECURE_KEY, secureKey);
                updateData.put(RSA_KEY, rsaEncryption.getPublicKey().toString());
                updateData.put(SESSION_ID, user + SLASH + enrypted.substring(0, SESSION_ID_SUBSTRING_LENGTH));
                updateData.put(EXPIRATION_KEY_DATE, System.currentTimeMillis() + MILLISECONDS_HOUR);

                writeUserSystemData(user, updateData);
            } else {
                response.put(STATUS, FieldConstant.STATUS_FAIL);
                response.put(FAILURE_REASON, "RSA not found!");
            }
        } else {
            response.put(STATUS, FieldConstant.STATUS_FAIL);
            response.put(FAILURE_REASON, "user or password is not valid");
        }

        return response;
    }

    private static String findRSAKey(Map<String, Object> message) {
        String rsaKey = (String) message.get("rsa-key");
        if (rsaKey == null || rsaKey.isEmpty()) {
            return readRSAKey((String) message.get(USER));
        } else {
            return rsaKey;
        }
    }

    private static Map<String, Object> returnFile(Map<String, Object> message) {
        String sessionId = (String) message.get(SESSION_ID);

        String userName = sessionId.split(SLASH)[0];
        String fileName = PATH_FILES + userName + SLASH + message.get("fileName");

        Map<String, Object> response = new HashMap<>();
        if (compareSessionId(userName, sessionId)) {
            if (keyNotExpired(userName)) {
                String secureKey = readSecureKey(userName);
                byte[] encryptedFile = encryptRequestedFileFile(fileName, secureKey);

                response.put(STATUS, STATUS_OK);
                response.put(CONTENT, new String(Base64.encodeBase64(encryptedFile)));
            } else {
                response.put(STATUS, FieldConstant.STATUS_FAIL);
                response.put(FAILURE_REASON, "Session key is expired");
            }
        } else {
            response.put(STATUS, FieldConstant.STATUS_FAIL);
            response.put(FAILURE_REASON, "File not found");
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
            return (String) map.get(SECURE_KEY);
        }
        return null;
    }

    private static String readRSAKey(String user) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            return (String) map.get(RSA_KEY);
        }
        return null;
    }

    private static boolean compareSessionId(String user, String sessionId) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            String fileSessionId = (String) map.get(SESSION_ID);
            return fileSessionId != null && fileSessionId.equals(sessionId);
        }
        return false;
    }

    private static boolean keyNotExpired(String user) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            double expirationKeyDate = (double) map.get(EXPIRATION_KEY_DATE);
            long longExpirationKeyDate = (long) expirationKeyDate;
            return longExpirationKeyDate > System.currentTimeMillis();
        }
        return false;
    }

    private static boolean authenticate(String user, String password) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            String filePassword = (String) map.get(PASSWORD);
            return filePassword != null && filePassword.equals(password);
        }
        return false;
    }

    private static Map<String, Object> readUserSystemData(String user) {
        try {
            byte[] file = Files.readAllBytes(Paths.get(PATH_FILES + user + PATH_SYSTEM_INFO));
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
            Files.write(Paths.get(PATH_FILES + user + PATH_SYSTEM_INFO), jsonData.getBytes());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
