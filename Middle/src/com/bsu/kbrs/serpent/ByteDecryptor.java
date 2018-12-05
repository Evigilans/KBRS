package com.bsu.kbrs.serpent;

import edu.rit.util.Packing;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ByteDecryptor {

    private Serpent serpent = new Serpent();

    public String decryptBytes(byte[] encryptedBytes, String secureKey) {
        byte[] key = secureKey.getBytes();
        serpent.setKey(key);

        byte[] iv = new byte[16];
        Packing.unpackIntLittleEndian(128, iv, 0);
        serpent.encrypt(iv);

        byte[] decryptedBytes = new byte[encryptedBytes.length];
        for (int i = 0; i < encryptedBytes.length; i += 16) {
            byte[] block = new byte[]{
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            for (int n = 0; n < 16 && n < encryptedBytes.length; n++) {
                block[n] = encryptedBytes[i + n];
            }
            byte[] savedForIV = Arrays.copyOf(block, 16);
            serpent.decrypt(block);
            for (int n = 0; n < 16; n++) {
                block[n] = (byte) (block[n] ^ iv[n]);
            }
            iv = savedForIV;

            System.arraycopy(block, 0, decryptedBytes, i, block.length);
        }

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
