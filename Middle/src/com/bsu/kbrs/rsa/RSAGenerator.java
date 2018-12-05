package com.bsu.kbrs.rsa;

import java.math.*;
import java.security.SecureRandom;

/**
 * RSA Generator class is used to calculate the private and public keys, based on a specified bit length.
 * Encrypt and Decrypt Methods also defined below.
 */
public class RSAGenerator {

    private RSAKey publicKey; //Public Key
    private RSAKey privateKey; //Private key
    private static final BigInteger ONE = BigInteger.ONE; //Value of 1 expressed as a BigInteger for ease of calculation

    /**
     * Object Constructor
     */
    public RSAGenerator(){

    }

    /**
     *
     * @param numbits Bit Length used to generate the various components
     */
    public void generate(int numbits) {
        //Generate p and q
        BigInteger p = BigInteger.probablePrime(numbits, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(numbits, new SecureRandom());
        //Compute n - modulus
        BigInteger n = p.multiply(q);
        //Compute Euler's totient function, phiN
        BigInteger p_minus_one = p.subtract(ONE);
        BigInteger q_minus_one = q.subtract(ONE);
        BigInteger phiN = p_minus_one.multiply(q_minus_one);
        //Calculate public exponent
        BigInteger e, d;
        do {
            e = BigInteger.probablePrime(numbits, new SecureRandom());
        } while ((e.compareTo(ONE) == 1) && (e.compareTo(phiN) == -1) && (e.gcd(phiN).compareTo(ONE) != 0));
        //Calculate private exponent
        d = e.modInverse(phiN);
        //Set Keys
        publicKey = new RSAKey(e,n);
        privateKey = new RSAKey(d,n);
    }


    public RSAKey getPublicKey() {
        return publicKey;
    }

    public RSAKey getPrivateKey() {
        return privateKey;
    }

}