package com.bsu.kbrs.client;

import com.bsu.kbrs.constant.FieldConstant;
import com.bsu.kbrs.constant.SystemConfigurationConstant;
import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAGenerator;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.serpent.ByteDecryptor;
import com.bsu.kbrs.serpent.FileEncryptor;
import com.bsu.kbrs.utils.MessageUtils;

import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class Client {

    private static final String NEW_KEYS_PARAM = "--new-keys";

    private static final String USAGE = "Client options: \n" +
            NEW_KEYS_PARAM + " - generates a new pair of rsa keys\n" +
            "usage:\n" +
            "java -jar client.jar [HOSTNAME][:PORT]\n" +
            "defaults:\n" +
            "HOSTNAME - localhost\n" +
            "PORT - " + SystemConfigurationConstant.SOCKET_PORT;

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

        Path privateFile = Paths.get(rsaDirectory.toString(), SystemConfigurationConstant.PRIVATE_KEY_FILE_NAME);
        try {
            Files.write(privateFile,
                    Collections.singletonList(rsaGenerator.getPrivateKey().toString()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Path publicFile = Paths.get(rsaDirectory.toString(), SystemConfigurationConstant.PUBLIC_KEY_FILE_NAME);
        try {
            Files.write(publicFile,
                    Collections.singletonList(rsaGenerator.getPublicKey().toString()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        markRsaKeyNotSent();

        privateKey = rsaGenerator.getPrivateKey();
        publicKey = rsaGenerator.getPublicKey();

        System.out.println("new keys generated");
    }

    private static boolean isRsaKeySent() {
        Path sentPath = Paths.get(getRsaKeyDirectory().toString(), SystemConfigurationConstant.RSA_KEYS_SENT_FILE);
        return Files.exists(sentPath);
    }

    private static void markRsaKeySent() {
        Path sentPath = Paths.get(getRsaKeyDirectory().toString(), SystemConfigurationConstant.RSA_KEYS_SENT_FILE);
        try {
            if (!Files.exists(sentPath)) {
                Files.createFile(sentPath);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void markRsaKeyNotSent() {
        Path sentPath = Paths.get(getRsaKeyDirectory().toString(), SystemConfigurationConstant.RSA_KEYS_SENT_FILE);
        try {
            Files.deleteIfExists(sentPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean readUpKeys() {
        Path rsaDirectory = getRsaKeyDirectory();
        Path privateFile = Paths.get(rsaDirectory.toString(), SystemConfigurationConstant.PRIVATE_KEY_FILE_NAME);
        Path publicFile = Paths.get(rsaDirectory.toString(), SystemConfigurationConstant.PUBLIC_KEY_FILE_NAME);

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
        request.put(FieldConstant.TYPE, FieldConstant.AUTH);
        if (!isRsaKeySent()) {
            request.put(FieldConstant.RSA_KEY, publicKey.toString());
        }
        request.put(FieldConstant.USER, login);
        request.put(FieldConstant.PASSWORD, DigestUtils.sha1Hex(password));

        return request;
    }

    private static Map<String, Object> createGetFilePayload(final String file, final String sessionId) {
        Map<String, Object> request = new HashMap<>();
        request.put(FieldConstant.TYPE, FieldConstant.GET_FILE);
        request.put("fileName", file);
        request.put(FieldConstant.SESSION_ID, sessionId);

        return request;
    }

    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("--help") || args[0].equals("-h"))) {
            System.out.println(USAGE);
            return;
        }

        boolean isNewKeyPram = false;
        String hostNamePort = "localhost:" + SystemConfigurationConstant.SOCKET_PORT;
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
            port = String.valueOf(SystemConfigurationConstant.SOCKET_PORT);
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

            mainLoop(scanner, login, password);
        }
    }


    private static void mainLoop(Scanner scanner, String login, String password) {
        Map<String, Object> helloPayload = createAuthRequestPayload(login, password);
        Map<String, Object> response = sendRequest(helloPayload);

        if (response != null) {
            String status = (String) response.get(FieldConstant.STATUS);

            final String failure = (String) response.get(FieldConstant.FAILURE_REASON);
            if (status != null && status.equals(FieldConstant.STATUS_FAIL)
                    && failure != null && failure.equals("RSA not found!")) {
                markRsaKeyNotSent();
                helloPayload = createAuthRequestPayload(login, password);
                response = sendRequest(helloPayload);

                status = (String) response.get(FieldConstant.STATUS);
            }

            if (status != null && status.equals(FieldConstant.STATUS_OK)) {
                markRsaKeySent();

                final RSAEncryption rsaEncryption = new RSAEncryption(publicKey, privateKey);

                final String encryptedKey = (String) response.get(FieldConstant.ENCRYPTION_KEY);

                final String decryptedKey = rsaEncryption.decrypt(new BigInteger(encryptedKey));
                final String sessionId = rsaEncryption.decrypt(
                        new BigInteger(((String) response.get(FieldConstant.SESSION_ID))));

                final String storageKey = rsaEncryption.decrypt(
                        new BigInteger((String)response.get(FieldConstant.STORAGE_KEY)));

                System.out.println("Enter Command");
                while (true) {
                    String command = scanner.nextLine().trim();
                    if (command.equalsIgnoreCase("getFile")) {
                        getFileCommand(scanner, sessionId, decryptedKey, storageKey);
                    } else if (command.equalsIgnoreCase("ls")) {
                        lsCommand();
                    } else if (command.equalsIgnoreCase("open")) {
                        openLocalFileCommand(scanner, storageKey);
                    }
                }
            } else {
                handleGenericError(response);
            }
        } else {
            System.out.println("Unrecognized ERROR!");
        }
    }

    private static void openLocalFileCommand(Scanner scanner, String storageKey) {
        System.out.println("Please enter fileName.");

        String requestedFile = scanner.next();
        Path localFilePath = Paths.get(getLocalStorageDirectory().toString(), requestedFile);

        try {
            byte[] encryptedContent = Files.readAllBytes(localFilePath);
            String content = new ByteDecryptor().decryptBytes(encryptedContent, storageKey);
            openText(content);
        } catch (IOException e) {
            System.out.println("Cannot open file " + requestedFile);
        }
    }

    private static Path getLocalStorageDirectory() {
        return Paths.get(System.getProperty("user.home"), ".kbrs_local");
    }

    private static void lsCommand() {
        Path localStorageDirectory = getLocalStorageDirectory();
        try {
            if (!Files.exists(localStorageDirectory)) {
                Files.createDirectories(localStorageDirectory);
            }

            List<Path> files = Files.list(localStorageDirectory).collect(Collectors.toList());
            if (files.size() == 0) {
                System.out.println("Nothing is stored locally");
            } else {
                for(Path file : files) {
                    System.out.println(file.getFileName().toString());
                }
            }
        } catch (IOException pE) {
            pE.printStackTrace();
        }

    }

    private static void getFileCommand(final Scanner scanner, final String sessionId,
                                       final String decryptSessionKey, final String storageKey) {
        System.out.println("Please enter fileName.");

        String requestedFile = scanner.next();
        System.out.println("Requesting file " + requestedFile);
        Map<String, Object> getFilePayload = createGetFilePayload(requestedFile, sessionId);
        Map<String, Object> getFileResponse = sendRequest(getFilePayload);
        System.out.println(MessageUtils.getGson().toJson(getFileResponse));

        if (getFileResponse != null) {
            final String getFileStatus = (String) getFileResponse.get(FieldConstant.STATUS);
            final String getFileFailure = (String) getFileResponse.get(FieldConstant.FAILURE_REASON);
            if (getFileStatus != null && getFileStatus.equals(FieldConstant.STATUS_FAIL) &&
                    getFileFailure != null && getFileFailure.equals("Session key is expired")) {

                System.out.println("Session is expired. Please login again.");
                System.exit(0);
            } else if (getFileStatus != null && getFileStatus.equals(FieldConstant.STATUS_OK)) {
                byte[] fileEncryptedContent = Base64.decodeBase64(((String) getFileResponse.get("content")).getBytes());
                String decryptedFileContent = new ByteDecryptor().decryptBytes(fileEncryptedContent, decryptSessionKey);
                saveLocalFile(requestedFile, decryptedFileContent, storageKey);
                openText(decryptedFileContent);
            } else {
                handleGenericError(getFileResponse);
            }
        } else {
            System.out.println("Unrecognized ERROR!");
        }
    }

    private static void saveLocalFile(final String fileName, final String content, final String storageKey) {
        Path localFilePath = Paths.get(getLocalStorageDirectory().toString(), fileName);

        byte[] fileBytes = new FileEncryptor().encrypt(content.getBytes(), storageKey);

        try {
            if (!Files.exists(localFilePath)) {
                if (!Files.exists(localFilePath.getParent())) {
                    Files.createDirectories(localFilePath.getParent());
                }

                Files.createFile(localFilePath);
            }
            Files.write(localFilePath, fileBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void openText(final String content) {
        try {
            File file = File.createTempFile("kbrs", ".txt");
            Files.write(Paths.get(file.toURI()), content.getBytes());
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().edit(file);
            } else {
                System.out.println("File content");
                System.out.println(content);
            }
            file.deleteOnExit();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void handleGenericError(Map<String, Object> pResponse) {
        final String failureReason = (String) pResponse.get(FieldConstant.FAILURE_REASON);
        if (failureReason != null) {
            System.out.println("ERROR: " + failureReason);
        } else {
            System.out.println("Unrecognized ERROR!");
        }
    }

}