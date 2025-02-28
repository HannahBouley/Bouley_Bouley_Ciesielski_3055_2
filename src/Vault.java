import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;
import merrimackutil.json.types.JSONObject;

/**
 * Vault class to manage the encrypted vault file.
 */
public class Vault {
    private static final String VAULT_JSON_PATH = "vault.json";
    private static final int GCM_TAG_LENGTH = 16;
    private static final int SALT_LENGTH = 16;
    private static final int VAULT_KEY_LENGTH = 32; // 256-bit vault key
    private static byte[] rootKey;  // Derived from user password
    private static byte[] vaultKey; // Used to encrypt/decrypt vault contents
    private static JSONObject vaultData; // In-memory vault contents

    /**
     * Load the vault from the vault.json file.
     * 
     * @throws Exception
     */
    public static void loadVault() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your vault password: ");
        String password = scanner.nextLine();
        
        File vaultFile = new File(VAULT_JSON_PATH);
        if (vaultFile.exists()) {
            byte[] fileData = Files.readAllBytes(vaultFile.toPath());

            // Extract salt from the first 16 bytes
            byte[] salt = new byte[SALT_LENGTH];
            System.arraycopy(fileData, 0, salt, 0, SALT_LENGTH);

            // Derive root key from user password
            rootKey = deriveKey(password, salt);

            // Extract encrypted vault key (next 48 bytes: 16-byte IV + 32-byte encrypted key)
            byte[] encryptedVaultKey = new byte[48];
            System.arraycopy(fileData, SALT_LENGTH, encryptedVaultKey, 0, 48);

            // Decrypt vault key using root key
            vaultKey = decryptAESGCM(encryptedVaultKey, rootKey);

            // Extract encrypted vault data (remaining bytes)
            byte[] encryptedVaultData = new byte[fileData.length - (SALT_LENGTH + 48)];
            System.arraycopy(fileData, SALT_LENGTH + 48, encryptedVaultData, 0, encryptedVaultData.length);

            // Decrypt vault data using vault key
            byte[] decryptedData = decryptAESGCM(encryptedVaultData, vaultKey);
            vaultData = new JSONObject(new String(decryptedData, StandardCharsets.UTF_8));

            System.out.println("Vault successfully loaded.");
        } else {
            System.out.println("No vault found. Creating a new one...");
            createNewVault(password);
        }
    }

    /**
     * Create a new vault with the given password.
     * 
     * @param password
     * @throws Exception
     */
    public static void createNewVault(String password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        // Derive root key from password
        rootKey = deriveKey(password, salt);

        // Generate a random vault key
        vaultKey = new byte[VAULT_KEY_LENGTH];
        new SecureRandom().nextBytes(vaultKey);

        // Create empty vault structure
        vaultData = new JSONObject();
        vaultData.put("services", new JSONObject());

        // Encrypt the vault key using root key
        byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey);

        // Encrypt vault data using vault key
        byte[] encryptedVaultData = encryptAESGCM(vaultData.toJSON().getBytes(StandardCharsets.UTF_8), vaultKey);

        // Write salt + encrypted vault key + encrypted vault data to vault.json
        try (FileOutputStream fos = new FileOutputStream(VAULT_JSON_PATH)) {
            fos.write(salt);
            fos.write(encryptedVaultKey);
            fos.write(encryptedVaultData);
        }

        System.out.println("New vault created and encrypted.");
    }

    /**
     * Seal the vault by saving the encrypted vault key and data to the vault.json file.
     * 
     * @throws Exception
     */
    public static void sealVault() throws Exception {
        if (vaultData == null) {
            System.out.println("No vault loaded to seal.");
            return;
        }

        // Encrypt the vault key using root key
        byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey);

        // Encrypt vault data using vault key
        byte[] encryptedVaultData = encryptAESGCM(vaultData.toJSON().getBytes(StandardCharsets.UTF_8), vaultKey);

        // Retrieve existing salt
        byte[] salt = new byte[SALT_LENGTH];
        try (FileInputStream fis = new FileInputStream(VAULT_JSON_PATH)) {
            fis.read(salt);
        }

        // Write salt + encrypted vault key + encrypted vault data to vault.json
        try (FileOutputStream fos = new FileOutputStream(VAULT_JSON_PATH)) {
            fos.write(salt);
            fos.write(encryptedVaultKey);
            fos.write(encryptedVaultData);
        }

        System.out.println("Vault sealed and saved.");
    }

    /**
     * Derive a key from the given password and salt using the SCrypt key derivation function.
     * 
     * @param password
     * @param salt
     * @return derived key
     */
    private static byte[] deriveKey(String password, byte[] salt) {
        return SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, 16384, 8, 1, 32);
    }

    /**
     * Encrypt data using AES-GCM with the given key.
     * 
     * @param data
     * @param key
     * @return encrypted data
     * @throws Exception
     */
    private static byte[] encryptAESGCM(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[12]; // 12-byte IV for GCM
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encryptedData = cipher.doFinal(data);

        // Combine IV + encrypted data
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(encryptedData);

        return outputStream.toByteArray();
    }

    /**
     * Decrypt data using AES-GCM with the given key.
     * 
     * @param encryptedData
     * @param key
     * @return decrypted data
     * @throws Exception
     */
    private static byte[] decryptAESGCM(byte[] encryptedData, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[12];
        System.arraycopy(encryptedData, 0, iv, 0, 12);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] data = new byte[encryptedData.length - 12];
        System.arraycopy(encryptedData, 12, data, 0, data.length);

        return cipher.doFinal(data);
    }
}
