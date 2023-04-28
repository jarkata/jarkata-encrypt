package cn.jarkata.encrypt;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class AesFactoryTest {

    @Test
    public void encrypt() throws Exception {
        SecretKeySpec secretKeySpec = AesFactory.genSecretKey("1234");
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

    @Test
    public void encrypt3() throws Exception {
        byte[] allBytes = Files.readAllBytes(Paths.get("/Users/data/lira/lira-server.jar"));
        byte[] encrypt = AesFactory.simpleEncrypt("1234567812345678", allBytes);
        System.out.println(encrypt.length);
        byte[] decrypt = AesFactory.simpleDecrypt("1234567812345678", encrypt);
        Files.write(Paths.get("/Users/data/code/lira-server.jar"), decrypt, StandardOpenOption.TRUNCATE_EXISTING);
    }
}