package cn.jarkata.encrypt;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RsaFactory {

    public static final String ALGORITHM_RSA = "RSA";
    public static final String PUBLIC_KEY = "PUBLIC_KEY";
    public static final String PRIVATE_KEY = "PRIVATE_KEY";

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

    public static String getPublicKey(Map<String, Key> dataMap) {
        RSAPublicKey publicKey = (RSAPublicKey) dataMap.get(PUBLIC_KEY);
        return JetBase64.encodeBase64(publicKey.getEncoded());
    }

    public static String getPrivateKey(Map<String, Key> dataMap) {
        RSAPrivateKey privateKey = (RSAPrivateKey) dataMap.get(PRIVATE_KEY);
        return JetBase64.encodeBase64(privateKey.getEncoded());
    }

    public static PublicKey getPublicKey(RSAPublicKey publicKey) throws Exception {
        return getPublicKey(publicKey.getEncoded());
    }


    public static PublicKey genPublicKey(String publicData) throws Exception {
        byte[] decodeBase64 = JetBase64.decodeBase64(publicData);
        return getPublicKey(decodeBase64);
    }


    public static PublicKey getPublicKey(byte[] publicKeyData) throws Exception {
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePublic(encodedKeySpec);
    }


    public static PrivateKey getPrivateKey(String privateKeyData) throws Exception {
        byte[] decodeBase64 = JetBase64.decodeBase64(privateKeyData);
        return getPrivateKey(decodeBase64);
    }

    public static PrivateKey getPrivateKey(RSAPrivateKey privateKey) throws Exception {
        return getPrivateKey(privateKey.getEncoded());
    }

    public static PrivateKey getPrivateKey(byte[] privateKeyData) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    /**
     * 公钥加密数据，并返回Base64编码的数据
     *
     * @param publicKey 公钥
     * @param data      明文
     * @return 密文数据
     */
    public static String encryptToString(PublicKey publicKey, String data) throws Exception {
        return JetBase64.encodeBase64(encrypt(publicKey, data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 加密数据，并返回Base64编码的数据
     *
     * @param privateKey 私钥
     * @param data       明文数据
     * @return 密文
     */
    public static String encryptToString(PrivateKey privateKey, String data) throws Exception {
        return JetBase64.encodeBase64(encrypt(privateKey, data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 使用公钥加密
     *
     * @param publicKey 公钥
     * @param data      被加密数据
     * @return 密文数据
     * @throws Exception 加密时发生异常
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.ENCRYPT_MODE, publicKey);
        return instance.doFinal(data);
    }

    /**
     * 使用私钥加密数据
     *
     * @param privateKey 私钥
     * @param data       明文数据
     * @return 密文数据
     * @throws Exception 加密发生异常
     */
    public static byte[] encrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.ENCRYPT_MODE, privateKey);
        return instance.doFinal(data);
    }

    /**
     * 根据私钥解密数据
     *
     * @param privateKey 私钥
     * @param data       密文数据
     * @return 明文数据
     */
    public static String decryptToString(PrivateKey privateKey, String data) throws Exception {
        final byte[] decodeBase64 = JetBase64.decodeBase64(data);
        return new String(decrypt(privateKey, decodeBase64), StandardCharsets.UTF_8);
    }

    /**
     * 根据公钥解密数据
     *
     * @param publicKey 公钥
     * @param data      密文
     * @return 明文数据
     */
    public static String decryptToString(PublicKey publicKey, String data) throws Exception {
        return new String(decrypt(publicKey, JetBase64.decodeBase64(data)), StandardCharsets.UTF_8);
    }

    /**
     * 使用私钥解密数据
     *
     * @param privateKey 私钥
     * @param data       密文数据
     * @return 明文数据
     * @throws Exception 解密发生异常
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.DECRYPT_MODE, privateKey);
        return instance.doFinal(data);
    }

    /**
     * 使用公钥解密数据
     *
     * @param publicKey 公钥
     * @param data      密文数据
     * @return 明文数据
     * @throws Exception 解密发生异常
     */
    public static byte[] decrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.DECRYPT_MODE, publicKey);
        return instance.doFinal(data);
    }


}