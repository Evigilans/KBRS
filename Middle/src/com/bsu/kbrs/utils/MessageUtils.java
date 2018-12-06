package com.bsu.kbrs.utils;

import com.google.gson.Gson;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Alex Turchynovich
 */
public class MessageUtils {

    private static final Gson gson = new Gson();

    public static void sendMessage(DataOutputStream dataOutputStream, Map pPayload) throws IOException {
        dataOutputStream.writeByte(0x1A); // magic number
        dataOutputStream.writeUTF(gson.toJson(pPayload));
    }

    @SuppressWarnings({"unchecked"})
    public static Map<String, Object> readMessage(DataInputStream pInputStream) throws IOException {
        byte magic = pInputStream.readByte();
        if (magic != 0x1A) {
            throw new IOException("Invalid message header");
        }

        String json = pInputStream.readUTF();

        Map<String, Object> map = new HashMap<>();
        return (Map<String, Object>) gson.fromJson(json, map.getClass());
    }

    public static Gson getGson() {
        return gson;
    }
}
