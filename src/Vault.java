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

import merrimackutil.json.types.JSONArray;
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
        Console console = System.console();
        if (console == null) {
            System.out.println("No console available.");
            return;
        }
    
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your vault password: ");
        char[] hiddenPassword = console.readPassword();
        String password = new String(hiddenPassword);
        scanner.close();
    
        File vaultFile = new File(VAULT_JSON_PATH);
        if (!vaultFile.exists()) {
            System.out.println("No vault found. Creating a new one...");
            createNewVault(password);
            return;
        }

        JSONObject vaultJson = JsonIO.readObject(vaultFile);
    
        byte[] salt = Base64.getDecoder().decode(vaultJson.getString("salt"));
        rootKey = deriveKey(password, salt);
    
        JSONObject vaultKeyObject = vaultJson.getObject("vaultkey");
        byte[] vaultIv = Base64.getDecoder().decode(vaultKeyObject.getString("iv"));
        byte[] encryptedVaultKey = Base64.getDecoder().decode(vaultKeyObject.getString("key"));
    
        vaultKey = decryptAESGCM(encryptedVaultKey, rootKey, vaultIv);
    
        // Load vault data
        vaultData = vaultJson;
        
        System.out.println("Vault successfully loaded.");
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

    // Generate IV for vault key encryption
    byte[] vaultIv = generateIv();

    // Encrypt the vault key using root key
    byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey, vaultIv);

    // Initialize the vault JSON structure
    vaultData = new JSONObject();
    vaultData.put("vaultkey", new JSONObject());
    vaultData.put("iv", Base64.getEncoder().encodeToString(vaultIv));
    vaultData.put("key", Base64.getEncoder().encodeToString(encryptedVaultKey));
    vaultData.put("passwords", new JSONArray());
    vaultData.put("privkeys", new JSONArray());
    
    System.out.println("New vault created and encrypted.");
    // Create an instance of Vault and call sealVault()
    Vault vaultInstance = new Vault();
    vaultInstance.sealVault(); 
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
        
            // Encrypt vault key using root key
            byte[] vaultIv = generateIv();
            byte[] encryptedVaultKey = encryptAESGCM(vaultKey, rootKey, vaultIv);
        
            // Store encrypted vault key
            vaultData.getObject("vaultkey").put("key", Base64.getEncoder().encodeToString(encryptedVaultKey));
            vaultData.put("iv", Base64.getEncoder().encodeToString(vaultIv));
            vaultData.put("key", Base64.getEncoder().encodeToString(encryptedVaultKey));
        
            // Write to vault.json
            try (PrintWriter out = new PrintWriter(VAULT_JSON_PATH)) {
                out.println(vaultData.toJSON());
            }
        
            System.out.println("Vault sealed and saved.");
        }







        public void addPassword(String service, String user, String password) throws Exception {
            byte[] iv = generateIv();
            byte[] encryptedPassword = encryptAESGCM(password.getBytes(StandardCharsets.UTF_8), vaultKey, iv);
        
            JSONObject entry = new JSONObject();
            entry.put("iv", Base64.getEncoder().encodeToString(iv));
            entry.put("service", service);
            entry.put("user", user);
            entry.put("pass", Base64.getEncoder().encodeToString(encryptedPassword));
        
            vaultData.getArray("passwords").add(entry);
            sealVault();
        }
        
        public void addPrivateKey(String service, String privateKey) throws Exception {
            byte[] iv = generateIv();
            byte[] encryptedPrivateKey = encryptAESGCM(privateKey.getBytes(StandardCharsets.UTF_8), vaultKey, iv);
        
            JSONObject entry = new JSONObject();
            entry.put("iv", Base64.getEncoder().encodeToString(iv));
            entry.put("service", service);
            entry.put("privkey", Base64.getEncoder().encodeToString(encryptedPrivateKey));
        
            vaultData.getArray("privkeys").add(entry);
            sealVault();
        }
        
        public String getPassword(String service) throws Exception {
            for (Object obj : vaultData.getArray("passwords")) {
                JSONObject entry = (JSONObject) obj;
                if (entry.getString("service").equals(service)) {
                    byte[] iv = Base64.getDecoder().decode(entry.getString("iv"));
                    byte[] encryptedPass = Base64.getDecoder().decode(entry.getString("pass"));
                    return new String(decryptAESGCM(encryptedPass, vaultKey, iv), StandardCharsets.UTF_8);
                }
            }
            return null;
        }
        
        public String getPrivateKey(String service) throws Exception {
            for (Object obj : vaultData.getArray("privkeys")) {
                JSONObject entry = (JSONObject) obj;
                if (entry.getString("service").equals(service)) {
                    byte[] iv = Base64.getDecoder().decode(entry.getString("iv"));
                    byte[] encryptedKey = Base64.getDecoder().decode(entry.getString("privkey"));
                    return new String(decryptAESGCM(encryptedKey, vaultKey, iv), StandardCharsets.UTF_8);
                }
            }
            return null;
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
