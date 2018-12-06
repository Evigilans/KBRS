package com.bsu.kbrs.utils;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Random;

public class ApplicationUtils {
    public static String generateRandomKey(int targetStringLength) {
        int leftLimit = 97;
        int rightLimit = 122;
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(targetStringLength);
        for (int i = 0; i < targetStringLength; i++) {
            int randomLimitedInt = leftLimit + (int) (random.nextFloat() * (rightLimit - leftLimit + 1));
            buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }

    public static byte[] appendFileWithSpaces(byte[] fileData) {
        int numberOfSpaces = 16 - fileData.length % 16;
        if (numberOfSpaces != 16) {
            byte[] destination = new byte[fileData.length + numberOfSpaces];
            byte[] spaces = new byte[numberOfSpaces];

            Arrays.fill(spaces, 0, numberOfSpaces, (byte) 32);
            System.arraycopy(fileData, 0, destination, 0, fileData.length);
            System.arraycopy(spaces, 0, destination, fileData.length, spaces.length);

            return destination;
        }
        return fileData;
    }
}
