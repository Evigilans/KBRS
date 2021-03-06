package com.bsu.kbrs.server;

import com.bsu.kbrs.constant.FieldConstant;
import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.serpent.ByteDecryptor;
import com.bsu.kbrs.serpent.FileEncryptor;
import com.bsu.kbrs.utils.ApplicationUtils;
import com.bsu.kbrs.utils.MessageUtils;
import com.bsu.kbrs.utils.SessionPair;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

import static com.bsu.kbrs.constant.FieldConstant.*;
import static com.bsu.kbrs.constant.SystemConfigurationConstant.*;

public class Server {
    private static Map<String, SessionPair> sessions = new HashMap<>();
    private static byte[] definitelyNotAKey = {115, 117, 112, 101, 114, 115, 101, 99, 114, 101, 116, 107, 101, 121};

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

                String storageKey = readUserStorageKey(user);
                if (storageKey == null) {
                    storageKey = ApplicationUtils.generateRandomKey(SESSION_KEY_LENGTH);
                }
                String encryptedStorageKey = rsaEncryption.encrypt(storageKey).toString();
                response.put(STORAGE_KEY, encryptedStorageKey);
                System.out.println("storageKey: " + storageKey);

                String sessionId = generateRandomString();
                SessionPair sessionPair = new SessionPair(user, System.currentTimeMillis() + MILLISECONDS_HOUR);
                sessions.put(sessionId, sessionPair);

                response.put(STATUS, STATUS_OK);
                response.put(ENCRYPTION_KEY, enrypted);
                response.put(SESSION_ID, rsaEncryption.encrypt(sessionId).toString());

                Map<String, Object> updateData = new HashMap<>();
                updateData.put(PASSWORD, password);
                updateData.put(SECURE_KEY, secureKey);
                updateData.put(STORAGE_KEY, storageKey);
                updateData.put(RSA_KEY, rsaEncryption.getPublicKey().toString());

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

    private static String readUserStorageKey(String user) {
        Map<String, Object> map = readUserSystemData(user);
        if (map != null) {
            return (String) map.get(STORAGE_KEY);
        }
        return null;
    }

    private static String generateRandomString() {
        int leftLimit = 97;
        int rightLimit = 122;
        int targetStringLength = 10;
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(targetStringLength);
        for (int i = 0; i < targetStringLength; i++) {
            int randomLimitedInt = leftLimit + (int)
                    (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }

    private static String findRSAKey(Map<String, Object> message) {
        String rsaKey = (String) message.get(RSA_KEY);
        if (rsaKey == null || rsaKey.isEmpty()) {
            return readRSAKey((String) message.get(USER));
        } else {
            return rsaKey;
        }
    }

    private static Map<String, Object> returnFile(Map<String, Object> message) {
        String sessionId = (String) message.get(SESSION_ID);

        System.out.println(sessionId);

        String userName = sessions.get(sessionId).getUserId();
        String fileName = PATH_FILES + userName + SLASH + message.get("fileName");

        Map<String, Object> response = new HashMap<>();
        if (userName != null) {
            if (keyNotExpired(sessionId)) {
                String secureKey = readSecureKey(userName);
                byte[] encryptedFile = encryptRequestedFileFile(fileName, secureKey);

                response.put(STATUS, STATUS_OK);
                response.put(CONTENT, new String(Objects.requireNonNull(Base64.encodeBase64(encryptedFile))));
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
        try {
            File requestedFile = new File(fileName);
            byte[] fileData = new byte[(int) requestedFile.length()];
            DataInputStream dataInputStream = new DataInputStream((new FileInputStream(requestedFile)));
            dataInputStream.readFully(fileData);
            dataInputStream.close();

            ByteDecryptor byteDecryptor = new ByteDecryptor();
            String tempDecryptedValue = byteDecryptor.decryptBytes(fileData, new String(definitelyNotAKey));

            FileEncryptor fileEncryptor = new FileEncryptor();
            return fileEncryptor.encryptFile(tempDecryptedValue.getBytes(), secureKey);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
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

    private static boolean keyNotExpired(String sessionId) {
        return sessions.get(sessionId).getExpirationDate() > System.currentTimeMillis();
    }

    private static boolean authenticate(String user, String password) {
        Map<String, Object> map = readUserSystemData(user);

        System.out.println(map);

        if (map != null) {
            String filePassword = (String) map.get(PASSWORD);
            return filePassword != null && filePassword.equals(password);
        }
        return false;
    }

    private static Map<String, Object> readUserSystemData(String user) {
        try {
            ByteDecryptor byteDecryptor = new ByteDecryptor();

            byte[] file = Files.readAllBytes(Paths.get(PATH_FILES + user + PATH_SYSTEM_INFO));
            String decryptedFile = byteDecryptor.decryptBytes(file, new String(definitelyNotAKey));
            Map<String, Object> map = new HashMap<>();
            map = MessageUtils.getGson().fromJson(decryptedFile, map.getClass());
            return map;
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    private static void writeUserSystemData(String user, Map<String, Object> data) {
        try {
            FileEncryptor fileEncryptor = new FileEncryptor();

            String jsonData = MessageUtils.getGson().toJson(data, data.getClass());
            byte[] encryptedFile = fileEncryptor.encryptFile(jsonData.getBytes(), new String(definitelyNotAKey));
            Files.write(Paths.get(PATH_FILES + user + PATH_SYSTEM_INFO), encryptedFile);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
