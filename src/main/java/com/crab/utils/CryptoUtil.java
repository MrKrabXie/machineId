package com.crab.utils;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.util.Base64;

@Slf4j
public class CryptoUtil {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256; // AES-256

    // Generate a new AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    // Encrypt data using AES with a given key
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Decrypt data using AES with a given key
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // Convert SecretKey to Base64 string
    public static String encodeKey(SecretKey key) {
        log.info("key:{}", key.toString());
        String s = Base64.getEncoder().encodeToString(key.getEncoded());
        log.info("encodeKey:{}", s);
        return s;
    }

    // Decode Base64 string to SecretKey
    public static SecretKey decodeKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
    }

}