package com.bsu.kbrs.serpent;

import com.bsu.kbrs.util.ApplicationUtils;
import edu.rit.util.Packing;

import java.io.*;

public class FileEncryptor {
    private static final int KEY_LENGTH = 16;
    private static final int BLOCK_SIZE = 16;

    private Serpent serpent = new Serpent();

    public byte[] encryptFile(String filename, String secureKey) {
        try {
            File inputFile = new File(filename);
            byte[] fileData = new byte[(int) inputFile.length()];
            DataInputStream inputStream = new DataInputStream((new FileInputStream(inputFile)));
            inputStream.readFully(fileData);
            inputStream.close();

            System.out.println("Secret key: " + secureKey);
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
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
