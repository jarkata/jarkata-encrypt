package cn.jarkata.encrypt;

import cn.jarkata.commons.utils.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Locale;
import java.util.Objects;

public class Sm4Factory {

    // 算法
    private static final String ALGORITHM_SM4 = "SM4";
    // 密钥长度128位
    private static final int DEFAULT_KEY_SIZE = 128;
    // 变换规则（CBC模式）
    private static final String TRANSFORMATION_CBC = "SM4/CBC/PKCS5Padding";
    // 变换规则（ECB模式）
    private static final String TRANSFORMATION_ECB = "SM4/ECB/PKCS5Padding";

    // 追加提BC提供器
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static String generateKey(String seeds) {
        SecretKeySpec secretKeySpec = genSecretKeySpec(seeds);
        byte[] specEncoded = secretKeySpec.getEncoded();
        return JaHex.encodeHex(specEncoded);
    }

    public static SecretKeySpec genSecretKeySpec(String seeds) {
        if (StringUtils.isBlank(seeds)) {
            throw new IllegalArgumentException("Seeds Blank");
        }
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_SM4, BouncyCastleProvider.PROVIDER_NAME);
            keyGenerator.init(128, new SecureRandom(seeds.getBytes(StandardCharsets.UTF_8)));
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretKeyEncoded = secretKey.getEncoded();
            return new SecretKeySpec(secretKeyEncoded, ALGORITHM_SM4);
        } catch (Exception ex) {
            throw new RuntimeException(ALGORITHM_SM4 + " GenSecretKey Error:", ex);
        }
    }


    /**
     * 加密（ECB模式）
     *
     * @param keyHex    秘钥HEX字符串
     * @param plainText 明文字符串
     * @return 加密后的HEX字符串
     */
    public static byte[] simpleEncrypt(SecretKeySpec secretKeySpec, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

    }

    /**
     * 解密（ECB模式）
     *
     * @param keyHex        秘钥HEX字符串
     * @param cipherDataHex 密文的HEX字符串
     * @return 解密后的明文
     */
    public static byte[] simpleDecrypt(SecretKeySpec secretKeySpec, byte[] encrypt) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(encrypt);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
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
            Cipher instance = Cipher.getInstance(TRANSFORMATION_ECB);
            //加密
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_SM4);
            instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION_ECB + " Encrypt Error:", ex);
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
            Cipher instance = Cipher.getInstance(TRANSFORMATION_ECB);
            //解密数据
            SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), ALGORITHM_SM4);
            instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return instance.doFinal(encrypt);
        } catch (Exception ex) {
            throw new RuntimeException(TRANSFORMATION_ECB + " Decrypt Error:", ex);
        }
    }


    /**
     * 加密（CBC模式）
     *
     * @param keyHex   秘钥HEX字符串
     * @param planText 明文字符串
     * @param ivHex    向量HEX字符串
     * @return 加密后的HEX字符串
     */
    public static String encrypt(String keyHex, String planText, String ivHex) {
        try {
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), ALGORITHM_SM4);
            // 创建IV向量
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(ivHex));

            // 初始化
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(planText.getBytes(StandardCharsets.UTF_8));

            return Hex.toHexString(outputBytes).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

    }

    /**
     * 解密（CBC模式）
     *
     * @param keyHex        秘钥HEX字符串
     * @param cipherDataHex 密文的HEX字符串
     * @param ivHex         向量HEX字符串
     * @return 解密后的明文
     */
    public static String decrypt(String keyHex, String cipherDataHex, String ivHex) {

        try {
            // 创建加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
            // 创建加密规则
            SecretKeySpec keySpec = new SecretKeySpec(Hex.decode(keyHex), ALGORITHM_SM4);
            // 创建IV向量
            IvParameterSpec ivSpec = new IvParameterSpec(Hex.decode(ivHex));

            // 初始化
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // 调用加密方法
            byte[] outputBytes = cipher.doFinal(Hex.decode(cipherDataHex));

            return new String(outputBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
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
