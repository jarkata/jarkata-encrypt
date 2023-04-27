package cn.jarkata.encrypt;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AESFactoryTest {

    @Test
    public void encrypt() throws Exception {
        SecretKeySpec secretKeySpec = AESFactory.genSecretKey("1234");
        byte[] encrypt = AESFactory.encrypt(secretKeySpec, "testtesttesttest");
        byte[] decrypt = AESFactory.decrypt(secretKeySpec, encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }

    @Test
    public void encrypt2() throws Exception {
        byte[] encrypt = AESFactory.encrypt("1234567812345678", "testtesttesttest");
        byte[] decrypt = AESFactory.decrypt("1234567812345678", encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }
}