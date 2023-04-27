package cn.jarkata.encrypt;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

public class RSAFactoryTest {

    @Test
    public void init() throws Exception {
        Map<String, Key> keyMap = RSAFactory.init(1024);
        RSAPublicKey key = (RSAPublicKey) keyMap.get(RSAFactory.PUBLIC_KEY);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyMap.get(RSAFactory.PRIVATE_KEY);
        PublicKey publicKey = RSAFactory.getPublicKey(key);

        byte[] publicKeyEncoded = publicKey.getEncoded();
        Base64.Encoder encoder = Base64.getEncoder();
        System.out.println("PUB:" + encoder.encodeToString(publicKeyEncoded));
        byte[] privateKeyEncoded = rsaPrivateKey.getEncoded();
        System.out.println("PRI:" + encoder.encodeToString(privateKeyEncoded));

        byte[] encrypt = RSAFactory.encrypt(publicKey, "test");

        PrivateKey privateKey = RSAFactory.getPrivateKey(rsaPrivateKey);

        byte[] decrypt = RSAFactory.decrypt(RSAFactory.getPrivateKey(rsaPrivateKey), encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));


        byte[] encrypt1 = RSAFactory.encrypt(privateKey, "test141234");

        byte[] decrypt2 = RSAFactory.decrypt(publicKey, encrypt1);
        System.out.println("PUB:" + new String(decrypt2, StandardCharsets.UTF_8));
    }

    @Test
    public void testInit() {
    }

    @Test
    public void getPublicKey() {
    }

    @Test
    public void getPrivateKey() {
    }

    @Test
    public void testGetPublicKey() {
    }

    @Test
    public void testGetPublicKey1() {
    }

    @Test
    public void genPublicKey() {
    }

    @Test
    public void testGetPrivateKey() {
    }

    @Test
    public void testGetPrivateKey1() {
    }

    @Test
    public void testGetPrivateKey2() {
    }

    @Test
    public void encrypt() {
    }

    @Test
    public void testEncrypt() {
    }

    @Test
    public void decrypt() {
    }

    @Test
    public void testDecrypt() {
    }
}