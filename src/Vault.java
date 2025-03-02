import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;

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

    // Generate a new IV
    private static byte[] iv = generateIv();

    /**
     * Load the vault from the vault.json file.
     * 
     * @throws Exception
     */
    public void loadVault() throws Exception {

        // Console class used for confidentiality
        Console console = System.console();

        if (console == null){
            System.out.println("No console available");
        }

        // Get user input for the password
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your vault password: ");
        char[] hiddenPassword = console.readPassword(); // Hide password echo

        String password = new String(hiddenPassword); // Store password into a new String type

        // Clean up
        scanner.close();
        
        // Load a new json if it exists, otherwise create a new one
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
            vaultKey = decryptAESGCM(encryptedVaultKey, rootKey, iv);

            // Extract encrypted vault data (remaining bytes)
            byte[] encryptedVaultData = new byte[fileData.length - (SALT_LENGTH + 48)];
            System.arraycopy(fileData, SALT_LENGTH + 48, encryptedVaultData, 0, encryptedVaultData.length);

            // Decrypt vault data using vault key
            byte[] decryptedData = decryptAESGCM(encryptedVaultData, vaultKey, iv);
            vaultData = new JSONObject();
            vaultData.put(new String(decryptedData, StandardCharsets.UTF_8), new JSONObject());
          
            

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
        byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey, iv);

        // Encrypt vault data using vault key
        byte[] encryptedVaultData = encryptAESGCM(vaultData.toJSON().getBytes(StandardCharsets.UTF_8), vaultKey, iv);

        
        // Write salt + encrypted vault key + encrypted vault data to vault.json
        
        vaultData.put("key", Base64.getEncoder().encodeToString(encryptedVaultKey));
        vaultData.put("key", Base64.getEncoder().encodeToString(encryptedVaultKey));

        try(PrintWriter out = new PrintWriter(VAULT_JSON_PATH)){
            out.println(vaultData.toJSON());
        }
        



        String encodedSalt = Base64.getEncoder().encodeToString(salt);
    
        vaultData.put("salt", encodedSalt);
        System.out.println(encodedSalt);    
      



        
        

        System.out.println("New vault created and encrypted.");
    }

    /**
     * Seal the vault by saving the encrypted vault key and data to the vault.json file.
     * 
     * @throws Exception
     */
    public void sealVault() throws Exception {
        if (vaultData == null) {
            System.out.println("No vault loaded to seal.");
            return;
        }

        // Encrypt the vault key using root key
        byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey, iv);

        // Encrypt vault data using vault key
        byte[] encryptedVaultData = encryptAESGCM(vaultData.toJSON().getBytes(StandardCharsets.UTF_8), vaultKey, iv);

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
    private static byte[] encryptAESGCM(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        /*
        byte[] iv = new byte[12]; // 12-byte IV for GCM
        new SecureRandom().nextBytes(iv);
        */

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
     * Generates a new IV
     * @return
     */
    private static byte[] generateIv(){
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        return iv;
    }

    /**
     * Generates a new secret key
     * @return
     */
    private static SecretKey generateKey(byte[] key){
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        return secretKey;
    }

    /**
     * Decrypt data using AES-GCM with the given key.
     * 
     * @param encryptedData
     * @param key
     * @return decrypted data
     * @throws Exception
     */
    private static byte[] decryptAESGCM(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        /*
        byte[] iv = new byte[12];
        System.arraycopy(encryptedData, 0, iv, 0, 12);
*/
        
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] data = new byte[encryptedData.length - 12];
        System.arraycopy(encryptedData, 12, data, 0, data.length);

        return cipher.doFinal(data);
    }
}
