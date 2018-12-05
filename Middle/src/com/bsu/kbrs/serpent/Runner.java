package com.bsu.kbrs.serpent;

import com.bsu.kbrs.rsa.RSAEncryption;
import com.bsu.kbrs.rsa.RSAGenerator;
import com.bsu.kbrs.rsa.RSAKey;
import com.bsu.kbrs.util.ApplicationUtils;

import java.math.BigInteger;

public class Runner {
    private static final int KEY_LENGTH = 16;

    public static void main(String[] args) {
        try {
            String secureKey = ApplicationUtils.generateRandomKey(KEY_LENGTH);

            FileEncryptor fileEncryptor = new FileEncryptor();
            ByteDecryptor byteDecryptor = new ByteDecryptor();

            byte[] encryptedBytes = fileEncryptor.encryptFile("files/user1/todo_list", secureKey);
            System.out.println(byteDecryptor.decryptBytes(encryptedBytes, secureKey));

            RSAGenerator rsaGenerator = new RSAGenerator();
            rsaGenerator.generate(512);

            RSAKey publicKey = rsaGenerator.getPublicKey();
            RSAKey privateKey = rsaGenerator.getPrivateKey();
            RSAEncryption rsaEncryption = new RSAEncryption(publicKey, privateKey);

            BigInteger enrypted = rsaEncryption.encrypt(secureKey);
            String decrypt = rsaEncryption.decrypt(enrypted);

            System.out.println(secureKey);
            System.out.println(enrypted);
            System.out.println(decrypt);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
