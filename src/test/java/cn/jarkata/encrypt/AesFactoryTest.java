package cn.jarkata.encrypt;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AesFactoryTest {

    @Test
    public void testGenSecretKey() {
        String secretKey = AesFactory.genSecretKey("test");
        System.out.println(secretKey.length());
        Assert.assertNotNull(secretKey);
    }

    @Test
    public void encrypt() throws Exception {
        SecretKeySpec secretKeySpec = AesFactory.genSecretKeySpec("1234");
        byte[] encrypt = AesFactory.simpleEncrypt(secretKeySpec, "testtesttesttest");
        byte[] decrypt = AesFactory.simpleDecrypt(secretKeySpec, encrypt);
        System.out.println(new String(decrypt, StandardCharsets.UTF_8));
    }

    @Test
    public void encrypt2() throws Exception {
        String password = "123456781234567812345678";
        password = "1234";
        final String encrypt = AesFactory.encryptToString(password, "testtesttesttest");
        final String decrypt = AesFactory.decryptToString(password, encrypt);
        System.out.println("解密后的数据：" + decrypt);
    }

    @Test
    public void encrypt4() throws Exception {
        String password = "123456781234567812345678";

        final byte[] encrypt1 = AesFactory.simpleEncrypt(password, "testtesttesttest".getBytes(StandardCharsets.UTF_8));
        final byte[] decrypt1 = AesFactory.simpleDecrypt(password, encrypt1);
        final String decrypt = new String(decrypt1, StandardCharsets.UTF_8);
        System.out.println("解密后的数据：" + decrypt);
    }


}