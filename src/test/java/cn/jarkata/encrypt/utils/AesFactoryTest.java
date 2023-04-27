package cn.jarkata.encrypt.utils;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AesFactoryTest {

    @Test
    public void encrypt() throws Exception {
        SecretKeySpec secretKeySpec = AesFactory.genSecretKey("1234");
        byte[] encrypt = AesFactory.encrypt(secretKeySpec, "testtesttesttest");
        byte[] decrypt = AesFactory.decrypt(secretKeySpec, encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }

    @Test
    public void encrypt2() throws Exception {
        byte[] encrypt = AesFactory.encrypt("1234567812345678", "testtesttesttest");
        byte[] decrypt = AesFactory.decrypt("1234567812345678", encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }
}