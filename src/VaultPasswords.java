import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JsonIO;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class VaultPasswords {
    private static final String VAULT_FILE = "vault.json";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static SecretKey vaultKey;
   

    public static void main(String[] args) {
        loadVault();
    }

    public static void loadVault() {
        File file = new File(VAULT_FILE);
        JSONObject vault;

        try {
            if (file.exists()) {
                vault = JsonIO.readObject(file);
                
                // Load vault key
                if (vault.containsKey("vaultkey")) {
                    JSONObject vaultKeyObject = vault.getObject("vaultkey");
                    String keyBase64 = vaultKeyObject.getString("key");

                    byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
                    vaultKey = new SecretKeySpec(keyBytes, "AES");
                } else {
                    throw new IllegalStateException("Vault key not found in vault.json");
                }
            } else {
                throw new IllegalStateException("Vault file not found");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void addPasswordAccount(String service, String username, String password) {
        try {
            File vaultFile = new File(VAULT_FILE);
            Collection vault;
            
            if (vaultFile.exists()) {
                // Read exisiting contents from the vault file
                vault = new Collection(JsonIO.readObject(vaultFile));
            } else {
                vault = new Collection();
            }

            JSONArray passwords = vault.containsKey("passwords") ? vault.getArray("passwords") : new JSONArray();

            // Generate IV (12 bytes)
            byte[] iv = generateIV();
            String encodedIV = Base64.getEncoder().encodeToString(iv);

            // Encrypt the password
            String encryptedPassword = encrypt(password, iv);

            // Create a new account object and put it in the passwords json array
            JSONObject account = new JSONObject();
            account.put("iv", encodedIV);
            account.put("service", service);
            account.put("user", username);
            account.put("pass", encryptedPassword);

            passwords.add(account);
            vault.addPasswordData(passwords);

            JsonIO.writeSerializedObject(vault, vaultFile);

            System.out.println("Password successfully added to vault.json");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encrypt(String data, byte[] iv) throws Exception {
        if (vaultKey == null) {
            throw new IllegalStateException("Vault key is not initialized");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, vaultKey, spec);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Adds a random password account to the vault.
     * 
     * @param service
     * @param username
     * @param passwordLength
     */
    public static void addRandomPasswordAccount(String service, String username, int passwordLength) {
        try {
            // Generate a random password
            String generatedPassword = generateRandomPassword(passwordLength);
            
            // Add it just like a normal password
            addPasswordAccount(service, username, generatedPassword);
            
            System.out.println("Generated password stored for service: " + service);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Generates a random password of specified length using secure random characters.
     * 
     * @param length
     * @return random password
     */
    private static String generateRandomPassword(int length) {
        final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
    
        for (int i = 0; i < length; i++) {
            password.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
    
        return password.toString();
    }

    /**
     * Adds a new key pair to the vault.
     * 
     * @param service
     */
    public static void addKeyPairService(String service) {
        try {
            File vaultFile = new File(VAULT_FILE);
            Collection vault;

            if (vaultFile.exists()) {
                vault = new Collection(JsonIO.readObject(vaultFile));
            } else {
                vault = new Collection();
            }

            JSONArray privateKeys = vault.containsKey("privKeys") ? vault.getArray("privKeys") : new JSONArray();

            // Generate IV (12 bytes)
            byte[] iv = generateIV();
            String encodedIV = Base64.getEncoder().encodeToString(iv);

            // Generate a cryptographic key pair
            KeyPair keyPair = generateKeyPair();
            String encodedPrivateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            // Store key pair in the vault
            JSONObject keyEntry = new JSONObject();
            keyEntry.put("iv", encodedIV);
            keyEntry.put("service", service);
            keyEntry.put("privkey", encodedPrivateKey);

            privateKeys.add(keyEntry);
            vault.addData("privKeys", privateKeys);

            JsonIO.writeSerializedObject(vault, vaultFile);

            System.out.println("Key-pair successfully generated and stored.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a new RSA key pair.
     * 
     * @return KeyPair
     * @throws NoSuchAlgorithmException
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}
