package cn.jarkata.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AesFactory {

    public static final String ALGORITHM_AES = "AES";
    public static final String TRANSFORMATION = "AES";

    public static byte[] encrypt(SecretKeySpec secretKeySpec, String data) throws Exception {
        //加密
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decrypt(SecretKeySpec secretKeySpec, byte[] encrypt) throws Exception {
        //解密
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return instance.doFinal(encrypt);
    }

    public static SecretKeySpec genSecretKey(String seeds) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
        keyGenerator.init(128, new SecureRandom(seeds.getBytes(StandardCharsets.UTF_8)));
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] secretKeyEncoded = secretKey.getEncoded();
        return new SecretKeySpec(secretKeyEncoded, ALGORITHM_AES);
    }


    public static byte[] encrypt(String password, String data) throws Exception {
        //加密
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decrypt(String password, byte[] encrypt) throws Exception {
        //解密
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher instance = Cipher.getInstance(TRANSFORMATION);
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return instance.doFinal(encrypt);
    }


}