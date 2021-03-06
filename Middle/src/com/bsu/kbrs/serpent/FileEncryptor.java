package com.bsu.kbrs.serpent;

import com.bsu.kbrs.utils.ApplicationUtils;
import edu.rit.util.Packing;

import java.io.*;

public class FileEncryptor {
    private static final int BLOCK_SIZE = 16;

    private Serpent serpent = new Serpent();

    public byte[] encrypt(byte[] fileData, String secureKey) {
        return getBytes(fileData, secureKey);
    }

    public byte[] encryptFile(byte[] fileData, String secureKey) {
        return getBytes(fileData, secureKey);
    }

    private byte[] getBytes(byte[] fileData, String secureKey) {
        byte[] key = secureKey.getBytes();
        serpent.setKey(key);

        byte[] iv = new byte[BLOCK_SIZE];
        Packing.unpackIntLittleEndian(128, iv, 0);
        serpent.encrypt(iv);

        fileData = ApplicationUtils.appendFileWithSpaces(fileData);
        byte[] encryptedBytes = new byte[fileData.length];
        for (int i = 0; i < fileData.length; i += BLOCK_SIZE) {
            byte[] block = new byte[]{
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            for (int n = 0; n < 16 && i + n < fileData.length; n++) {
                block[n] = (byte) (fileData[i + n] ^ iv[n]);
            }
            serpent.encrypt(block);
            iv = block;

            System.arraycopy(block, 0, encryptedBytes, i, block.length);
        }

        return encryptedBytes;
    }

    public byte[] encryptFile(String filename, String secureKey) {
        DataInputStream inputStream = null;
        try {
            File inputFile = new File(filename);
            byte[] fileData = new byte[(int) inputFile.length()];
            inputStream = new DataInputStream((new FileInputStream(inputFile)));
            inputStream.readFully(fileData);
            return encrypt(fileData, secureKey);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }


}