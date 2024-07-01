package com.crab.utils;

import com.crab.machine.SysUtils;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {

    private static final String APP_NAME = "Cognition";

    public static void main(String[] args) {
        try {
            // Generate or load AES key
            File keyFile = new File(FileStorageUtil.getStorageFile(APP_NAME) + ".key");
            SecretKey secretKey;

            if (keyFile.exists()) {
                // Load existing key
                String encodedKey = new String(Files.readAllBytes(Paths.get(keyFile.getPath())));
                secretKey = CryptoUtil.decodeKey(encodedKey);
            } else {
                // Generate new key
                secretKey = CryptoUtil.generateAESKey();
                String encodedKey = CryptoUtil.encodeKey(secretKey);
                Files.write(Paths.get(keyFile.getPath()), encodedKey.getBytes());
            }

            // Example: Encrypt and save machine code
//            String machineCode = "ABC123"; // Replace with actual machine code
            String machineCode = SysUtils.getMachineSlash4(); // Replace with actual machine code


            byte[] encryptedMachineCode = CryptoUtil.encrypt(machineCode.getBytes(StandardCharsets.UTF_8), secretKey);
            Files.write(FileStorageUtil.getStorageFile(APP_NAME).toPath(), encryptedMachineCode);

            // Example: Decrypt and read machine code
            byte[] encryptedData = Files.readAllBytes(FileStorageUtil.getStorageFile(APP_NAME).toPath());
            byte[] decryptedData = CryptoUtil.decrypt(encryptedData, secretKey);
            String decryptedMachineCode = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("Decrypted machine code: " + decryptedMachineCode);  //5687c3d5-cb167c08-1a0e09f7-c52d710d

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}