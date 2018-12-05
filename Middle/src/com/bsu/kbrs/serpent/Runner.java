package com.bsu.kbrs.serpent;

import edu.rit.util.Packing;

import java.io.*;
import java.util.Arrays;

public class Runner {
    /**
     * Main function encrypts the contents of the input file, storing the result in an output file
     * args either specifies N or
     * input filename, output filename, key (up to 32 bytes in hex), nonce (integer), and [e]ncrypt or [d]ecrypt
     */

    public static void main(String[] args) {
        Serpent serpent = new Serpent();
        try {
            String mode = "dec";
            File file_in = new File("data/output.txt");
            byte[] fileData = new byte[(int) file_in.length()];
            DataInputStream in_stream = new DataInputStream((new FileInputStream(file_in)));
            in_stream.readFully(fileData);
            in_stream.close();
            byte[] key = "3453fssf4".getBytes();
            //set key
            serpent.setKey(key);
            //setup file writing
            File file_out = new File("data/input.txt");
            DataOutputStream out_stream = new DataOutputStream((new FileOutputStream(file_out)));
            byte[] iv = new byte[16];
            //Create Nonce from 4th argument.
            Packing.unpackIntLittleEndian(128, iv, 0);
            serpent.encrypt(iv);
            //File encryption in CBC mode
            if (mode.equals("enc")) {
                for (int i = 0; i < fileData.length; i += 16) {
                    byte[] block = new byte[]{
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    };
                    for (int n = 0; n < 16 && i + n < fileData.length; n++) {
                        block[n] = (byte) (fileData[i + n] ^ iv[n]);
                    }
                    serpent.encrypt(block);
                    iv = block;
                    out_stream.write(block, 0, block.length);
                }
            }
            //File decryption in CBC mode
            else if (mode.equals("dec")) {
                for (int i = 0; i < fileData.length; i += 16) {
                    byte[] block = new byte[]{
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    };
                    for (int n = 0; n < 16 && n < fileData.length; n++) {
                        block[n] = (byte) (fileData[i + n]);
                    }
                    byte[] savedForIV = Arrays.copyOf(block, 16);
                    serpent.decrypt(block);
                    for (int n = 0; n < 16; n++) {
                        block[n] = (byte) (block[n] ^ iv[n]);
                    }
                    iv = savedForIV;
                    out_stream.write(block, 0, block.length);
                }
            } else {
                System.out.println("Encrypt/Decrypt option invalid, input e or d as 5th argument.");
            }
            out_stream.close();
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }
}
