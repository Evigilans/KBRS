package com.bsu.kbrs.rsa;

import java.math.BigInteger;

/**
 * Key class used to store the key's Component and Modulus
 */
public class RSAKey {

    private BigInteger component; //Component
    private BigInteger modulus; //Modulus

    /**
     * Object Constructor
     *
     * @param component Component of Key
     * @param modulus   Modulus
     */
    RSAKey(BigInteger component, BigInteger modulus) {
        this.component = component;
        this.modulus = modulus;
    }

    /**
     * Method used to return the Component of the Key
     *
     * @return BigInteger value of key's Component
     */
    public BigInteger getComponent() {
        return component;
    }

    /**
     * Method used to return the Modulus
     *
     * @return BigInteger value of Modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Prints to screen Key Information
     */
    @Override
    public String toString() {
        return getComponent() + ";" + getModulus();
    }

    public static RSAKey fromString(String key) {
        String[] pair = key.replaceAll("[^;\\d]", "").split(";");
        if (pair.length > 1) {
            return new RSAKey(new BigInteger(pair[0]), new BigInteger(pair[1]));
        }

        return null;
    }
}