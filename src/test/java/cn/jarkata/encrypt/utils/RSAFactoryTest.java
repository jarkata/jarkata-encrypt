package cn.jarkata.encrypt.utils;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class RSAFactoryTest {

    @Test
    public void init() throws Exception {
        Map<String, Key> keyMap = RSAFactory.init(1024);
        RSAPublicKey key = (RSAPublicKey) keyMap.get(RSAFactory.PUBLIC_KEY);
        PublicKey publicKey = RSAFactory.getPublicKey(key);
        byte[] encrypt = RSAFactory.encrypt(publicKey, "test");
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyMap.get(RSAFactory.PRIVATE_KEY);
        PrivateKey privateKey = RSAFactory.getPrivateKey(rsaPrivateKey);

        byte[] decrypt = RSAFactory.decrypt(RSAFactory.getPrivateKey(rsaPrivateKey), encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));


        byte[] encrypt1 = RSAFactory.encrypt(privateKey, "test141234");

        byte[] decrypt2 = RSAFactory.decrypt(publicKey, encrypt1);
        System.out.println("PUB:" + new String(decrypt2, StandardCharsets.UTF_8));
    }
}