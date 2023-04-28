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

public class RsaFactoryTest {

    @Test
    public void init() throws Exception {
        Map<String, Key> keyMap = RsaFactory.init(1024);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyMap.get(RsaFactory.PUBLIC_KEY);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyMap.get(RsaFactory.PRIVATE_KEY);

        byte[] publicKeyEncoded = rsaPublicKey.getEncoded();
        Base64.Encoder encoder = Base64.getEncoder();
        System.out.println("PUB:" + encoder.encodeToString(publicKeyEncoded));
        byte[] privateKeyEncoded = rsaPrivateKey.getEncoded();
        String privateEncode = encoder.encodeToString(privateKeyEncoded);
        System.out.println("PRI:" + privateEncode);

        PrivateKey privateKey1 = RsaFactory.getPrivateKey(privateEncode);
        System.out.println(privateKey1);

        PublicKey publicKey = RsaFactory.getPublicKey(rsaPublicKey);
        byte[] encrypt = RsaFactory.encrypt(publicKey, "test");

        PrivateKey privateKey = RsaFactory.getPrivateKey(rsaPrivateKey);

        byte[] decrypt = RsaFactory.decrypt(RsaFactory.getPrivateKey(rsaPrivateKey), encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));


        byte[] encrypt1 = RsaFactory.encrypt(privateKey, "test141234");

        byte[] decrypt2 = RsaFactory.decrypt(publicKey, encrypt1);
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