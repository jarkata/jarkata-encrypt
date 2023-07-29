package cn.jarkata.encrypt;

import cn.jarkata.commons.utils.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;

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
     * 根据随机因子生成密钥Key值，并以16进制数据返回
     *
     * @param seeds 随机因子
     * @return 16进制密钥
     */
    public static String genSecretKey(String seeds) {
        SecretKeySpec secretKeySpec = genSecretKeySpec(seeds);
        byte[] specEncoded = secretKeySpec.getEncoded();
        return JaHex.encodeHex(specEncoded);
    }

    /**
     * 生成安全密钥
     *
     * @param seeds 随机因子
     * @return 安全密钥
     */
    public static SecretKeySpec genSecretKeySpec(String seeds) {
        if (StringUtils.isBlank(seeds)) {
            throw new IllegalArgumentException("Seeds Blank");
        }
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGenerator.init(128, new SecureRandom(seeds.getBytes(StandardCharsets.UTF_8)));
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretKeyEncoded = secretKey.getEncoded();
            return new SecretKeySpec(secretKeyEncoded, ALGORITHM_AES);
        } catch (Exception ex) {
            throw new RuntimeException(ALGORITHM_AES + " GenSecretKey Error:", ex);
        }
    }

    public static byte[] simpleEncrypt(SecretKeySpec secretKeySpec, String plainText) {
        if (StringUtils.isBlank(plainText)) {
            throw new IllegalArgumentException("PlainText Blank");
        }
        if (Objects.isNull(secretKeySpec)) {
            throw new IllegalArgumentException("secretKeySpec Null");
        }
        //加密
        try {
            Cipher instance = Cipher.getInstance(TRANSFORMATION);
            instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return instance.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION + " Encrypt Error:", ex);
        }
    }

    public static byte[] simpleDecrypt(SecretKeySpec secretKeySpec, byte[] encrypt) {
        if (Objects.isNull(encrypt) || encrypt.length == 0) {
            throw new IllegalArgumentException("EncryptText Blank");
        }
        if (Objects.isNull(secretKeySpec)) {
            throw new IllegalArgumentException("secretKeySpec Null");
        }
        //解密
        try {
            Cipher instance = Cipher.getInstance(TRANSFORMATION);
            instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return instance.doFinal(encrypt);
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION + " Decrypt Error:", ex);
        }
    }

    /**
     * 加密数据，并返回Base64的字符串
     *
     * @param password 密码
     * @param data     明文数据
     * @return 密文数据
     */
    public static String encryptToString(String password, String data) {
        if (StringUtils.isBlank(password) || StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Param Blank");
        }
        final byte[] encrypt = simpleEncrypt(password, data.getBytes(StandardCharsets.UTF_8));
        return JaBase64.encodeBase64(encrypt);
    }

    /**
     * 解密数据，并返回明文字符串
     *
     * @param password 密码
     * @param data     密文数据
     * @return 明文数据
     */
    public static String decryptToString(String password, String data) {
        if (StringUtils.isBlank(password) || StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Param Blank");
        }
        final byte[] base64 = JaBase64.decodeBase64(data);
        final byte[] decrypt = simpleDecrypt(password, base64);
        return new String(decrypt, StandardCharsets.UTF_8);
    }


    /**
     * 解密数据
     *
     * @param password 密码
     * @param data     数据
     * @return 加密后的数据
     */
    public static byte[] simpleEncrypt(String password, byte[] data) {
        if (StringUtils.isBlank(password) || Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Param Blank");
        }
        try {
            password = wrapPassword(password);
            Cipher instance = Cipher.getInstance(TRANSFORMATION);
            //加密
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_AES);
            instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION + " Encrypt Error:", ex);
        }
    }

    /**
     * 解密数据
     *
     * @param password 密码
     * @param encrypt  加密数据
     * @return 解密后的明文数据
     */
    public static byte[] simpleDecrypt(String password, byte[] encrypt) {
        if (StringUtils.isBlank(password) || Objects.isNull(encrypt) || encrypt.length == 0) {
            throw new IllegalArgumentException("Param Blank");
        }
        try {
            password = wrapPassword(password);
            Cipher instance = Cipher.getInstance(TRANSFORMATION);
            //解密数据
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_AES);
            instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return instance.doFinal(encrypt);
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION + " Decrypt Error:", ex);
        }
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