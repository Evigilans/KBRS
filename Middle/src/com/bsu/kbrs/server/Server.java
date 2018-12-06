package com.bsu.kbrs.server;

import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAGenerator;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.util.ApplicationUtils;
import com.bsu.kbrs.utils.MessageUtils;
import com.google.gson.Gson;
import com.sun.javaws.security.AppContextUtil;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.function.ObjLongConsumer;

public class Server {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(9090);
            while (true) {
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                Map<String, Object> message = MessageUtils.readMessage(inputStream);
                String type = (String) message.get("type");
                System.out.println(type);

                if (type.equals("auth")) {
                    String user = (String) message.get("user");
                    String password = (String) message.get("password");
                    String rsaKey = (String) message.get("rsa-key");

                    Map<String, Object> response = new HashMap<>();
                    response.put("type", "auth");
                    if (authenticate(user, password)) {
                        response.put("status", "OK");

                        RSAEncryption rsaEncryption = new RSAEncryption();
                        rsaEncryption.setPublicKey(RSAKey.fromString(rsaKey));

                        BigInteger enrypted = rsaEncryption.encrypt(ApplicationUtils.generateRandomKey(32));

                        response.put("encryption_key", enrypted.toString());
                    } else {
                        response.put("status", "FAIL");
                        response.put("failureReason", "user or password is not valid");
                    }

                    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                    MessageUtils.sendMessage(outputStream, response);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean authenticate(String user, String password) {
        try {
            byte[] file = Files.readAllBytes(Paths.get("files/" + user + "/system_info/_info"));
            Map<String, Object> map = new HashMap<>();
            map = MessageUtils.getGson().fromJson(new String(file), map.getClass());
            return map.get("password") != null && map.get("password").equals(password);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        return false;
    }
}
