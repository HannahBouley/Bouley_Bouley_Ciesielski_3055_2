import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

/**
 * Vault class to manage the encrypted vault file.
 */
public class Vault{
    private static final String VAULT_JSON_PATH = "vault.json";
    private static final String HASHED_PASSWORD_PATH = "password.hash";
    private static final String HASHED_SALT_PATH = "salt.hash";
    private static final int GCM_TAG_LENGTH = 16;
    private static final int SALT_LENGTH = 16;
    private static final int VAULT_KEY_LENGTH = 32; // 256-bit vault key
    
    private static byte[] vaultKeyIv;
    private static SecretKey rootKey;  // Derived from user password
    private static SecretKey vaultKey; // Used to encrypt/decrypt vault contents
    private static JSONObject vaultData; // In-memory vault contents
    private static SecretKey secretKey;
    private static byte[] encryptedVaultKey;
    private static byte[] encryptedRootKey;
    private static byte[] iv;
 
    private static File saltFile;
    private static String password;
    private static byte[] salt;
    private static File passwordFile;
    private static File vaultFile = new File(VAULT_JSON_PATH);
    private static Collection collection;

    /**
     * Load the vault from the vault.json file.
     * 
     * @throws Exception
     */
    public void loadVault() throws Exception {

        // Add provider
        Security.addProvider(new BouncyCastleProvider());
        Console console = System.console();

        if (console == null){
            System.out.println("No console available");
        }

        // Check for required files
        if (!Files.exists(Paths.get(HASHED_PASSWORD_PATH)) && !Files.exists(Paths.get(HASHED_SALT_PATH)) && !Files.exists(Paths.get(VAULT_JSON_PATH))){
           
            System.out.println("Enter a new vault password: ");
            char[] hiddenPassword = console.readPassword(); // Hide password echo
           
            password = new String(hiddenPassword); // Store password into a new String type

            // Create the password file which will store the hashed password
            passwordFile = new File(HASHED_PASSWORD_PATH);
            saltFile = new File(HASHED_SALT_PATH);

            // Generate salt
            salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            Files.write(Paths.get(HASHED_SALT_PATH), salt);

            // Create hashed password
            String hashedPassword = hashPassword(password, salt);
            Files.write(Paths.get(HASHED_PASSWORD_PATH), hashedPassword.getBytes());

            // Generate a new vault key (to be encrypted by the root key)
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(256);
            vaultKey = gen.generateKey();

            // Generate new Iv
            vaultKeyIv = new byte[12];
            new SecureRandom().nextBytes(vaultKeyIv);

            // Generate a new root key from the password
            encryptedRootKey = deriveKey(password, salt);
            rootKey = new SecretKeySpec(encryptedRootKey, "AES");

            // The encrypted vault key
            encryptedVaultKey = encryptAESGCM(vaultKey.getEncoded(), rootKey, vaultKeyIv);
            
            createNewVault(password); // Create a new vault

        }

            else // If the files already exist
            
            {

                collection = new Collection(JsonIO.readObject(new File(VAULT_JSON_PATH)));

                // Get password input
                System.out.println("Enter the vault password: ");
                char[] hiddenPassword = console.readPassword();
                byte[] salt = Files.readAllBytes(Paths.get(HASHED_SALT_PATH));

                String password = new String(hiddenPassword);

                // Check to see if the hashed password is the same
                String storedHashed = new String(Files.readAllBytes(Paths.get(HASHED_PASSWORD_PATH)));
            
                String enteredHashed = hashPassword(password, salt);
            
                if (enteredHashed.equals(storedHashed)){
                    System.out.println("Access Granted");

                    encryptedRootKey = deriveKey(password, salt);
                    rootKey = new SecretKeySpec(encryptedRootKey, "AES");
            
                    byte[] fileData = Files.readAllBytes(vaultFile.toPath());
        
                    // Extract encrypted vault key (next 48 bytes: 16-byte IV + 32-byte encrypted key)
                    //encryptedVaultKey = new byte[48];
                    //System.arraycopy(fileData, SALT_LENGTH, encryptedVaultKey, 0, 48);
        
                    // Decrypt the vault key by using the root key
                    encryptedVaultKey = decryptAESGCM(Base64.getDecoder().decode(collection.getKeyData("key")), rootKey, Base64.getDecoder().decode(collection.getIvData("iv")));
                    
                    // Extract encrypted vault data (remaining bytes)
                    byte[] encryptedVaultData = new byte[fileData.length - (SALT_LENGTH + 48)];
                    System.arraycopy(fileData, SALT_LENGTH + 48, encryptedVaultData, 0, encryptedVaultData.length);
        
                    // Decrypt vault data using vault key  
                    vaultKey = new SecretKeySpec(encryptedVaultKey, "AES");
                    // byte[] decryptedData = decryptAESGCM(Files.readAllBytes(new File(VAULT_JSON_PATH).toPath()), vaultKey, Base64.getDecoder().decode(collection.getIvData("iv")));
                    vaultData = new JSONObject();
                    // vaultData.put(new String(decryptedData, StandardCharsets.UTF_8), new JSONObject());
                  
                    System.out.println("Vault successfully loaded.");
                } else {
                    System.out.println("Incorrect password. Access denied.");
                    System.exit(1);
                }    
            }       
    }

    /**
     * Hashes a specified password
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return Base64.getEncoder().encodeToString(factory.generateSecret(spec).getEncoded());
    }
    

    /**
     * Create a new vault with the given password.
     * 
     * @param password
     * @throws Exception
     */
    public static void createNewVault(String password) throws Exception {
        // Set up initial collection of objects
        collection = new Collection();

        // Add vaules
        collection.addSaltValue(Base64.getEncoder().encodeToString(salt));
        collection.addIv(Base64.getEncoder().encodeToString(vaultKeyIv));
        collection.addKey(Base64.getEncoder().encodeToString(encryptedVaultKey));

        // Write serialized format
        JsonIO.writeSerializedObject(collection, new File(VAULT_JSON_PATH));

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
        encryptedVaultKey = encryptAESGCM(vaultKey.getEncoded(), rootKey, vaultKeyIv);

        // Encrypt vault data using vault key
        byte[] encryptedVaultData = encryptAESGCM(Files.readAllBytes(new File(VAULT_JSON_PATH).toPath()), vaultKey, vaultKeyIv);

        // Retrieve existing salt
        byte[] salt = collection.getSaltValue("salt").getBytes();

        // Write salt + encrypted vault key + encrypted vault data to vault.json
        collection.addSaltValue(Base64.getEncoder().encodeToString(salt));
        collection.addIv(Base64.getEncoder().encodeToString(vaultKeyIv));
        collection.addKey(Base64.getEncoder().encodeToString(encryptedVaultKey));

        JsonIO.writeSerializedObject(collection, new File(VAULT_JSON_PATH));
        
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
    private static byte[] encryptAESGCM(byte[] plainData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);    
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(plainData);
    }

    /**
     * Decrypt data using AES-GCM with the given key.
     * 
     * @param encryptedData
     * @param key
     * @return decrypted data
     * @throws Exception
     */
    private static byte[] decryptAESGCM(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv); // 128
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(encryptedData);
    }
}
