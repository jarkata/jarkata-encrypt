package cn.jarkata.encrypt;

import cn.jarkata.commons.utils.StringUtils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * RSA算法工厂类
 */
public class RsaFactory {

    /**
     * 算法名称
     */
    public static final String ALGORITHM_RSA = "RSA";
    /**
     * 公钥Key值常量
     */
    public static final String PUBLIC_KEY = "PUBLIC_KEY";
    /**
     * 私钥Key值常量
     */
    public static final String PRIVATE_KEY = "PRIVATE_KEY";

    /**
     * 初始化密钥对
     *
     * @param keySize 密钥长度
     * @return 公私钥对
     * @throws Exception 初始化密钥失败时发生
     */
    public static Map<String, Key> init(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Key> dataMap = new HashMap<>();
        dataMap.put(PUBLIC_KEY, publicKey);
        dataMap.put(PRIVATE_KEY, privateKey);
        return dataMap;
    }

    /**
     * 获取公钥
     *
     * @param dataMap 初始化密钥Map
     * @return 公钥字符串，Base64编码
     */
    public static String getPublicKey(Map<String, Key> dataMap) {
        RSAPublicKey publicKey = (RSAPublicKey) dataMap.get(PUBLIC_KEY);
        return JaBase64.encodeBase64(publicKey.getEncoded());
    }

    /**
     * 私钥字符串
     *
     * @param dataMap 初始化密钥Map
     * @return 私钥字符串，Base64编码
     */
    public static String getPrivateKey(Map<String, Key> dataMap) {
        RSAPrivateKey privateKey = (RSAPrivateKey) dataMap.get(PRIVATE_KEY);
        return JaBase64.encodeBase64(privateKey.getEncoded());
    }

    /**
     * 公钥对象
     *
     * @param publicKey 公钥对象
     * @return 公钥对象
     */
    public static PublicKey getPublicKey(RSAPublicKey publicKey) {
        Objects.requireNonNull(publicKey, "RSAPublicKey Null");
        return getPublicKey(publicKey.getEncoded());
    }


    /**
     * 根据公钥数据，获取公钥对象
     *
     * @param publicData 公钥Base64编码数据
     * @return 公钥对象
     */
    public static PublicKey genPublicKey(String publicData) {
        byte[] decodeBase64 = JaBase64.decodeBase64(publicData);
        return getPublicKey(decodeBase64);
    }


    /**
     * 根据公钥字节数组获取公钥对象
     *
     * @param publicKeyData 公钥字节数组
     * @return 公钥对象
     */
    public static PublicKey getPublicKey(byte[] publicKeyData) {
        try {
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyData);
            KeyFactory keyFactory = getKeyFactoryInstance();
            return keyFactory.generatePublic(encodedKeySpec);
        } catch (Exception ex) {
            throw new RuntimeException("Get PublicKey Error:", ex);
        }
    }


    /**
     * 根据私钥Base64字符串获取私钥对象
     *
     * @param privateKeyData Base64编码私钥
     * @return 私钥对象
     */
    public static PrivateKey getPrivateKey(String privateKeyData) {
        byte[] decodeBase64 = JaBase64.decodeBase64(privateKeyData);
        return getPrivateKey(decodeBase64);
    }

    /**
     * RSA私钥对象，获取私钥
     *
     * @param privateKey 私钥对象
     * @return 私钥对象
     */
    public static PrivateKey getPrivateKey(RSAPrivateKey privateKey) {
        Objects.requireNonNull(privateKey, "RSAPrivateKey Null");
        return getPrivateKey(privateKey.getEncoded());
    }

    /**
     * RSA私钥数组，获取私钥
     *
     * @param privateKeyData 私钥数组
     * @return 私钥对象
     */
    public static PrivateKey getPrivateKey(byte[] privateKeyData) {
        Objects.requireNonNull(privateKeyData, "PrivateKeyData Null");
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
            KeyFactory keyFactory = getKeyFactoryInstance();
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception ex) {
            throw new RuntimeException("Get PrivateKey Error:", ex);
        }
    }

    /**
     * 密钥工厂
     *
     * @return 密钥工厂对象
     */
    private static KeyFactory getKeyFactoryInstance() {
        try {
            return KeyFactory.getInstance(ALGORITHM_RSA);
        } catch (Exception ex) {
            throw new RuntimeException("Get KeyFactory Error:", ex);
        }
    }

    /**
     * 公钥加密数据，并返回Base64编码的数据
     *
     * @param publicKey 公钥
     * @param data      明文
     * @return 密文数据
     */
    public static String encryptToString(PublicKey publicKey, String data) {
        if (Objects.isNull(publicKey) || StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Param Null");
        }
        return JaBase64.encodeBase64(encrypt(publicKey, data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 加密数据，并返回Base64编码的数据
     *
     * @param privateKey 私钥
     * @param data       明文数据
     * @return 密文
     */
    public static String encryptToString(PrivateKey privateKey, String data) {
        if (Objects.isNull(privateKey) || StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Param Null");
        }
        return JaBase64.encodeBase64(encrypt(privateKey, data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 使用公钥加密
     *
     * @param publicKey 公钥
     * @param data      被加密数据
     * @return 密文数据
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] data) {
        if (Objects.isNull(publicKey) || Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Param Null");
        }
        try {
            Cipher instance = getCipherInstance();
            instance.init(Cipher.ENCRYPT_MODE, publicKey);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException("Using PublicKey Encrypt Error:", ex);
        }
    }

    /**
     * 使用私钥加密数据
     *
     * @param privateKey 私钥
     * @param data       明文数据
     * @return 密文数据
     */
    public static byte[] encrypt(PrivateKey privateKey, byte[] data) {
        if (Objects.isNull(privateKey) || Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Param Null");
        }
        try {
            Cipher instance = getCipherInstance();
            instance.init(Cipher.ENCRYPT_MODE, privateKey);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException("Using PrivateKey Encrypt Error:", ex);
        }
    }

    /**
     * 根据私钥解密数据
     *
     * @param privateKey 私钥
     * @param data       密文数据
     * @return 明文数据
     */
    public static String decryptToString(PrivateKey privateKey, String data) {
        if (Objects.isNull(privateKey) || StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Param Null");
        }
        final byte[] decodeBase64 = JaBase64.decodeBase64(data);
        return new String(decrypt(privateKey, decodeBase64), StandardCharsets.UTF_8);
    }

    /**
     * 根据公钥解密数据
     *
     * @param publicKey 公钥
     * @param data      密文
     * @return 明文数据
     */
    public static String decryptToString(PublicKey publicKey, String data) {
        return new String(decrypt(publicKey, JaBase64.decodeBase64(data)), StandardCharsets.UTF_8);
    }

    /**
     * 使用私钥解密数据
     *
     * @param privateKey 私钥
     * @param data       密文数据
     * @return 明文数据
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] data) {
        if (Objects.isNull(privateKey) || Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Param Null");
        }
        try {
            Cipher instance = getCipherInstance();
            instance.init(Cipher.DECRYPT_MODE, privateKey);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException("Decrypt Error:", ex);
        }
    }

    /**
     * 使用公钥解密数据
     *
     * @param publicKey 公钥
     * @param data      密文数据
     * @return 明文数据
     */
    public static byte[] decrypt(PublicKey publicKey, byte[] data) {
        if (Objects.isNull(publicKey) || Objects.isNull(data) || data.length == 0) {
            throw new IllegalArgumentException("Param Null");
        }
        try {
            Cipher instance = getCipherInstance();
            instance.init(Cipher.DECRYPT_MODE, publicKey);
            return instance.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException("Decrypt Error:", ex);
        }
    }

    private static Cipher getCipherInstance() {
        try {
            return Cipher.getInstance(ALGORITHM_RSA);
        } catch (Exception ex) {
            throw new RuntimeException("Get Cipher Error:", ex);
        }
    }


}