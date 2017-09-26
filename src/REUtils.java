import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Formatter;

public class REUtils {
    private static final char[] sHexTable = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    /**
     * Read n bytes from the given lib at given offset
     *
     * @param libName the library name
     * @param decimalOffset the offset
     * @param count the byte count
     * @return the stdout of dd
     */
    public static String readLib(String libName, int decimalOffset, int count) {
        return execShellCmd("dd if=" + libName + " skip=" + decimalOffset + " bs=1 count=" + count);
    }

    /**
     * Write the payload into the given lib at given offset
     *
     * @param libName the library name
     * @param payload the payload to write
     * @param decimalOffset the offset
     * @return the stdout of dd
     */
    public static String writeLib(String libName, byte[] payload, int decimalOffset) {
        try {
            FileOutputStream fos = new FileOutputStream("tmp");
            fos.write(payload);
            fos.close();
            return execShellCmd("dd if=tmp of=" + libName + " seek=" + decimalOffset + " obs=1 conv=notrunc");
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * Exec a shell cmd
     *
     * @param cmd the command to execute
     * @return the std out with the result or error
     */
    public static String execShellCmd(String cmd) {
        StringBuilder output = new StringBuilder();
        Process process;
        try {
            process = Runtime.getRuntime().exec(cmd);
            process.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line)
                        .append("\n");
            }
            reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = reader.readLine()) != null) {
                output.append(line)
                        .append("\n");
            }
        } catch (Exception ignored) {
        }

        return output.toString();
    }

    /**
     * Pull a library from android data dir
     *
     * @param targetPackage the package name of the target app
     * @param libName the library name
     * @return whether if the pull was successful
     */
    public static boolean pullLib(String targetPackage, String libName) {
        String result = execShellCmd("adb shell su -c cp /data/data/" + targetPackage + "/lib/" + libName + " /sdcard/");
        if (result.isEmpty()) {
            execShellCmd("adb pull /sdcard/" + libName);
            return true;
        }

        return false;
    }

    /**
     * Push a library to android data dir
     *
     * @param targetPackage the package name of the target app
     * @param libName the library name
     * @return whether if the push was successful
     */
    public static boolean pushLib(String targetPackage, String libName) {
        String result = execShellCmd("adb push " + libName + " /sdcard/");
        if (result.trim().replace("\n", "").endsWith(libName)) {
            execShellCmd("adb shell su -c cp /sdcard/" + libName + " /data/data/" + targetPackage + "/lib/" + libName);
            return true;
        }

        return false;
    }

    /**
     * Convert an hex string to buffer
     *
     * @param s the hex string
     * @return the converted buffer
     */
    public static byte[] hexToBuf(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }

    /**
     * Convert a buffer to an hex string
     * @param bytes the buffer
     * @return the converted hex string
     */
    public static String bufToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        char[] hexChars = new char[bytes.length*2];
        int v;

        for(int j=0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j*2] = sHexTable[v>>>4];
            hexChars[j*2 + 1] = sHexTable[v & 0x0F];
        }

        return new String(hexChars);
    }

    /**
     * Print a buffer in hexdump style
     *
     * @param b the buffer to print
     * @return a formatted string which looks like a standard hexdump
     */
    public static String hexDump(byte[] b) {
        StringBuilder sb = new StringBuilder();
        StringBuilder sbb = new StringBuilder();
        Formatter formatter = new Formatter(sb);
        for (int j = 1; j < b.length + 1; j++) {
            if (j % 16 == 1) {
                sb.append(" ");
                sb.append(sbb.toString());
                sbb = new StringBuilder();
                sb.append("\n");
            }
            byte[] bc = new byte[1];
            bc[0] = b[j - 1];
            formatter.format("%02X", bc[0]);
            String s = new String(bc);
            sbb.append(s.replace("\n", " "));
            if (j % 4 == 0) {
                sb.append(" ");
                sbb.append(" ");
            }
        }
        sb.append("\n");
        return sb.toString();
    }
}
