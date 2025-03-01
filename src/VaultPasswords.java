import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JsonIO;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
                if (vault.has("vaultkey")) {
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
            JSONObject vault;
            
            if (vaultFile.exists()) {
                vault = JsonIO.readObject(vaultFile);
            } else {
                vault = new JSONObject();
            }

            JSONArray passwords = vault.has("passwords") ? vault.getArray("passwords") : new JSONArray();

            // Generate IV (12 bytes)
            byte[] iv = generateIV();
            String encodedIV = Base64.getEncoder().encodeToString(iv);
            String encryptedPassword = encrypt(password, iv);

            JSONObject account = new JSONObject();
            account.put("iv", encodedIV);
            account.put("service", service);
            account.put("user", username);
            account.put("pass", encryptedPassword);

            passwords.add(account);
            vault.put("passwords", passwords);

            // Write JSON manually using PrintWriter (matches VaultKey behavior)
            try (PrintWriter writer = new PrintWriter(vaultFile, StandardCharsets.UTF_8)) {
                writer.write(vault.toString());
            }

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
}
