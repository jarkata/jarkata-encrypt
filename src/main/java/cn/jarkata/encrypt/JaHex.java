package cn.jarkata.encrypt;

import org.bouncycastle.util.encoders.Hex;

public class JaHex {

    public static String encodeHex(byte[] data) {
        return Hex.toHexString(data);
    }

    public static byte[] decodeHex(String hexStr) {
        return Hex.decode(hexStr);
    }
}
