import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.io.File;
import java.io.PrintWriter;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import merrimackutil.json.types.JSONArray;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.parser.JSONParser;

public class vaultkey {
    private static final int VAULT_KEY_SIZE = 32; // 256-bit key
    private static final int IV_SIZE = 12; // 96-bit IV for AES-GCM
    private static final String VAULT_FILE = "vault.json";

    public static void main(String[] args) {
        generatevaultkey();
    }

    public static void generatevaultkey() {
        SecureRandom secureRandom = new SecureRandom();

        // Generate Vault Key (32 bytes for AES-256)
        byte[] keyBytes = new byte[VAULT_KEY_SIZE];
        secureRandom.nextBytes(keyBytes);
        String encodedKey = Base64.getEncoder().encodeToString(keyBytes);

        // Generate IV (12 bytes for AES-GCM)
        byte[] ivBytes = new byte[IV_SIZE];
        secureRandom.nextBytes(ivBytes);
        String encodedIV = Base64.getEncoder().encodeToString(ivBytes);

        // Verify that decoding the key returns exactly 32 bytes
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        if (decodedKey.length != VAULT_KEY_SIZE) {
            throw new IllegalStateException("Decoded key length is not 32 bytes!");
        }

        // Create vault key object
        JSONObject vaultkeyObject = new JSONObject();
        vaultkeyObject.put("iv", encodedIV);
        vaultkeyObject.put("key", encodedKey);

        // Load or create vault.json
        JSONObject vault;
        File vaultFile = new File(VAULT_FILE);
        try {
            if (vaultFile.exists()) {
                vault = JsonIO.readObject(vaultFile);
            } else {
                vault = new JSONObject();
            }
            
            // Store the vaultkey in vault.json
            vault.put("vaultkey", vaultkeyObject);
            
            // Write JSON as a string manually
            try (PrintWriter writer = new PrintWriter(vaultFile, StandardCharsets.UTF_8)) {
                writer.write(vault.toString());
            }
            System.out.println("Vault key successfully generated and stored in vault.json");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
