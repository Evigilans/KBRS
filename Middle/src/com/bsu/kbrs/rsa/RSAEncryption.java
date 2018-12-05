package com.bsu.kbrs.rsa;

import java.math.BigInteger;

public class RSAEncryption {

    private RSAKey publicKey; //Public Key
    private RSAKey privateKey; //Private key

    public RSAEncryption() {
    }

    public RSAEncryption(RSAKey pPublicKey, RSAKey pPrivateKey) {
        publicKey = pPublicKey;
        privateKey = pPrivateKey;
    }

    /**
     * Method used to encrypt a message string
     *
     * @param msg Message string to be encrypted
     * @return BigInteger value of encrypted message
     */
    public BigInteger encrypt(String msg) {
        return (new BigInteger(msg.getBytes())).modPow(publicKey.getComponent(), publicKey.getModulus());
    }

    /**
     * Method used to decrypt a message
     *
     * @param encrypt_msg Encrypted message as a BigInteger
     * @return BigInteger value of decrypted string
     */
    public String decrypt(BigInteger encrypt_msg) {
        BigInteger result = encrypt_msg.modPow(privateKey.getComponent(), privateKey.getModulus());
        StringBuilder decrypted = new StringBuilder();
        //BigInteger must be converted to a byte array in order to rebuild the original message
        for (byte b : result.toByteArray()) {
            decrypted.append((char) b);
        }

        return decrypted.toString();
    }


    public RSAKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAKey pPublicKey) {
        publicKey = pPublicKey;
    }

    public RSAKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAKey pPrivateKey) {
        privateKey = pPrivateKey;
    }
}
