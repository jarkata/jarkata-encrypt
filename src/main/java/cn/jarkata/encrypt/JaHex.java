package cn.jarkata.encrypt;

import org.bouncycastle.util.encoders.Hex;

public class JaHex {

    /**
     * 16进制编码
     *
     * @param data 字节数组
     * @return 编码后的数据
     */
    public static String encodeHex(byte[] data) {
        return Hex.toHexString(data);
    }

    /**
     * 十六进制解码
     *
     * @param hexStr 十六进制数据
     * @return 字节数组
     */
    public static byte[] decodeHex(String hexStr) {
        return Hex.decode(hexStr);
    }
}
