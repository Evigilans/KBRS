package com.bsu.kbrs.client;


import com.bsu.kbrs.rsa.RSAGenerator;
import com.bsu.kbrs.rsa.RSAKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

public class Client {

    private static final String NEW_KEYS_PARAM = "--new-keys";
    private static final String PUBLIC_KEY_FILE_NAME = "public";
    private static final String PRIVATE_KEY_FILE_NAME = "public";

    private static String USAGE = "Client options: \n" +
            NEW_KEYS_PARAM + " - generates a new pair of rsa keys\n" +
            "usage:\n" +
            "java -jar client.jar [HOSTNAME][:PORT]\n" +
            "defaults:\n" +
            "HOSTNAME - localhost\n" +
            "PORT - TBD";

    private static Path getRsaKeyDirectory() {
        return Paths.get(System.getProperty("user.home"), ".rsa_keys_secret");
    }

    private static RSAKey privateKey;
    private static RSAKey publicKey;

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
            e.printStackTrace();
        }

        return privateKey != null && publicKey != null;
    }

    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("--help") || args[0].equals("-h"))) {
            System.out.println(USAGE);
        }

        final boolean isNewKeyPram = args.length > 0 &&
                (args[0].equalsIgnoreCase(NEW_KEYS_PARAM) ||
                args[args.length - 1].equalsIgnoreCase(NEW_KEYS_PARAM));
        
        if (!readUpKeys() || isNewKeyPram) {
            generateNewKeys();
        }

        System.out.println(privateKey);

    }

}
