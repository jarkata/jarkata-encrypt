package cn.jarkata.encrypt;

import cn.jarkata.commons.utils.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Aes算法加密的工具类
 */
public class AesFactory {

    /**
     * 算法常量
     */
    public static final String ALGORITHM_AES = "AES";
    /**
     * 算法常量
     */
    public static final String TRANSFORMATION = "AES";//"AES_256/CBC/NoPadding";

    /**
     * 生成安全密钥
     *
     * @param seeds 随机因子
     * @return 安全密钥
     * @throws Exception 生成安全密钥失败时的异常
     */
    public static SecretKeySpec genSecretKey(String seeds) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
        keyGenerator.init(128, new SecureRandom(seeds.getBytes(StandardCharsets.UTF_8)));
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] secretKeyEncoded = secretKey.getEncoded();
        return new SecretKeySpec(secretKeyEncoded, ALGORITHM_AES);
    }

    public static byte[] simpleEncrypt(SecretKeySpec secretKeySpec, String data) throws Exception {
        //加密
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] simpleDecrypt(SecretKeySpec secretKeySpec, byte[] encrypt) throws Exception {
        //解密
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return instance.doFinal(encrypt);
    }

    /**
     * 加密数据，并返回Base64的字符串
     *
     * @param password 密码
     * @param data     明文数据
     * @return 密文数据
     * @throws Exception 加密发生异常时抛出的异常
     */
    public static String encryptToString(String password, String data) throws Exception {
        final byte[] encrypt = simpleEncrypt(password, data.getBytes(StandardCharsets.UTF_8));
        return JetBase64.encodeBase64(encrypt);
    }

    /**
     * 解密数据，并返回明文字符串
     *
     * @param password 密码
     * @param data     密文数据
     * @return 明文数据
     * @throws Exception 解密失败时抛出异常
     */
    public static String decryptToString(String password, String data) throws Exception {
        final byte[] base64 = JetBase64.decodeBase64(data);
        final byte[] decrypt = simpleDecrypt(password, base64);
        return new String(decrypt, StandardCharsets.UTF_8);
    }


    /**
     * 解密数据
     *
     * @param password 密码
     * @param data     数据
     * @return 加密后的数据
     * @throws Exception 加密失败
     */
    public static byte[] simpleEncrypt(String password, byte[] data) throws Exception {
        password = wrapPassword(password);
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        //加密
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_AES);
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return instance.doFinal(data);
    }

    /**
     * 解密数据
     *
     * @param password 密码
     * @param encrypt  加密数据
     * @return 解密后的明文数据
     * @throws Exception 解密发生异常
     */
    public static byte[] simpleDecrypt(String password, byte[] encrypt) throws Exception {
        password = wrapPassword(password);
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        //解密数据
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_AES);
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return instance.doFinal(encrypt);
    }

    /**
     * 确保密码长度达32位
     *
     * @param password 密码
     * @return 32位密码
     */
    private static String wrapPassword(String password) {
        return StringUtils.leftPad(password, 32, "0");
    }


}