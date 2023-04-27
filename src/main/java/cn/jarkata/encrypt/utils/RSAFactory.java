package cn.jarkata.encrypt.utils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAFactory {

    public static final String ALGORITHM_RSA = "RSA";
    public static final String PUBLIC_KEY = "PUBLIC_KEY";
    public static final String PRIVATE_KEY = "PRIVATE_KEY";
    private static final Map<String, Key> dataMap = new HashMap<>();

    public static Map<String, Key> init(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        dataMap.put(PUBLIC_KEY, publicKey);
        dataMap.put(PRIVATE_KEY, privateKey);
        return dataMap;
    }

    public static PublicKey getPublicKey(RSAPublicKey publicKey) throws Exception {
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePublic(encodedKeySpec);
    }

    public static PrivateKey getPrivateKey(RSAPrivateKey privateKey) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    public static byte[] encrypt(PublicKey publicKey, String data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.ENCRYPT_MODE, publicKey);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] encrypt(PrivateKey privateKey, String data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.ENCRYPT_MODE, privateKey);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }


    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.DECRYPT_MODE, privateKey);
        return instance.doFinal(data);
    }


    public static byte[] decrypt(PublicKey privateKey, byte[] data) throws Exception {
        Cipher instance = Cipher.getInstance(ALGORITHM_RSA);
        instance.init(Cipher.DECRYPT_MODE, privateKey);
        return instance.doFinal(data);
    }


}