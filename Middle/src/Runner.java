import com.bsu.kbrs.serpent.ByteDecryptor;
import com.bsu.kbrs.serpent.FileEncryptor;

import java.io.*;

public class Runner {
    private static byte[] definitelyNotAKey = {115, 117, 112, 101, 114, 115, 101, 99, 114, 101, 116, 107, 101, 121};

    public static void main(String[] args) throws IOException {
        String key = new String(definitelyNotAKey);

/*
        File inputFile = new File("files/user1/system_info/_info");
        byte[] fileData = new byte[(int) inputFile.length()];
        DataInputStream inputStream = new DataInputStream((new FileInputStream(inputFile)));
        inputStream.readFully(fileData);

        FileEncryptor fileEncryptor = new FileEncryptor();
        byte[] encrypted = fileEncryptor.encryptFile(fileData, key);

        File file_out = new File("files/user1/system_info/_info");
        DataOutputStream out_stream = new DataOutputStream((new FileOutputStream(file_out)));
        out_stream.write(encrypted);
*/

        File inputFile = new File("files/user1/system_info/_info");
        byte[] fileData = new byte[(int) inputFile.length()];
        DataInputStream inputStream = new DataInputStream((new FileInputStream(inputFile)));
        inputStream.readFully(fileData);
        ByteDecryptor byteDecryptor = new ByteDecryptor();
        System.out.println(byteDecryptor.decryptBytes(fileData, key));

    }
}
