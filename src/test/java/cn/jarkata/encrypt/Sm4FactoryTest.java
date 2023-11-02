package cn.jarkata.encrypt;

import org.junit.Test;

import static org.junit.Assert.*;

public class Sm4FactoryTest {

    @Test
    public void generateKey() {
        String generateKey = Sm4Factory.generateKey("nucc");
        System.out.println(generateKey);
    }
}