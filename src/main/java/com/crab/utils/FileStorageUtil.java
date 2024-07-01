package com.crab.utils;

import java.io.File;

public class FileStorageUtil {

    public static File getStorageFile(String appName) {
        String userHome = System.getProperty("user.home");
        String osName = System.getProperty("os.name").toLowerCase();
        File storageDir;

        if (osName.contains("win")) {
            // Windows
            storageDir = new File(userHome, "AppData/Roaming/" + appName);
        } else if (osName.contains("mac")) {
            // macOS
            storageDir = new File(userHome, "Library/Application Support/" + appName);
        } else {
            // Linux or other OS (handle accordingly)
            storageDir = new File(userHome, "." + appName.toLowerCase());
        }

        if (!storageDir.exists()) {
            storageDir.mkdirs(); // Create directories if they don't exist
        }

        return new File(storageDir, "machine_code.json");
    }

}