package cn.jarkata.encrypt;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class JaHexTest {

    @Test
    public void encodeHex() {
        String hex = JaHex.encodeHex("1234".getBytes(StandardCharsets.UTF_8));
        byte[] decodedHex = JaHex.decodeHex(hex);
        System.out.println(new String(decodedHex, StandardCharsets.UTF_8));
    }

}