import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Scanner;

import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import merrimackutil.json.types.JSONArray;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.parser.JSONParser;

/**
 * Driver class for the password manager application.
 */
class Driver {

    private static final String VAULT_JSON_PATH = "vault.json";
    private static File vaultFile = new File(VAULT_JSON_PATH);

    private static Collection col;
    private static boolean addService = false;
    private static boolean addUserName = false;
    private static boolean generatePassword = false;
    private static boolean generateKeyPair = false;

    private static String service = null;
    private static String user = null;
    private static int passwordLen = 0;
    private static String password;
    private static String key;
    private static Vault vault = new Vault();
    

    public static void main(String[] args) {
        // Load (unseal) the vault at startup
       
        try {
            vault.loadVault();
        } catch (FileNotFoundException e) {
            System.out.println("Vault file not found: " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (Exception e) {
            System.out.println("Error loading vault: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Load a new collection with the objects already in the json file
        try {
            col = new Collection(JsonIO.readObject(new File(VAULT_JSON_PATH)));

        } catch (Exception e) {
            System.out.println("Could not find file");
            e.printStackTrace();
            System.exit(1);
        }

        // Ensure vault is sealed before the application exits
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                System.out.println("Sealing vault before exit...");
                vault.sealVault();
            } catch (Exception e) {
                System.err.println("Error sealing vault: " + e.getMessage());
            }
        }));

        // Display the help menu if no args are inputted and return immediately
        if (args.length < 1) {
            System.out.println(Menu.DisplayMenuText());
            return;
        }
        
        handleCommandLineInputs(args);
    }


    /**
     * Handles commands from the command line interface
     * @param args
     */
    public static void handleCommandLineInputs(String[] args) {
        // An array of options
        LongOption[] argsList = new LongOption[5];

        argsList[0] = new LongOption("add", false, 'a');
        argsList[1] = new LongOption("service", true, 's');
        argsList[2] = new LongOption("user", true, 'u');
        argsList[3] = new LongOption("gen", true, 'g');
        argsList[4] = new LongOption("key", true, 'k');

        // The current option being processed
        Tuple<Character, String> currOpt = null;

        // Set up a new parser to parse the options
        OptionParser parser = new OptionParser(args);
        parser.setOptString("as:u:g:");
        parser.setLongOpts(argsList);

        // Gets the next option in the command line args
        while (parser.getOptIdx() != args.length) {
            currOpt = parser.getLongOpt(false);
            if (currOpt == null) continue;

            switch (currOpt.getFirst()) {
                case 'a':
                    addService = true;
                    break;
                case 's':
                    service = currOpt.getSecond();
                    
                    break;
                case 'u':
                    user = currOpt.getSecond();
                  
                    break;
                case 'g':
                    passwordLen = Integer.parseInt(currOpt.getSecond());
                    break;

                case 'k':
                    key = currOpt.getSecond();

                    break;

                case '?':
                   
                    break;
                default:
                    break;
            }

        }

              // Add a password, service, and username to the vault
              if (addService && service != null && user != null){
                Console console = System.console();

                if (passwordLen != 0){
                    if (passwordLen < 7){
                      
                
                        
                        if (console == null){
                            System.out.println("No console available");
                            System.exit(1);
                        } else {
                            VaultPasswords.addRandomPasswordAccount(service, user, passwordLen, col);
                        }


                    }
                }

                if (console == null){
                    System.out.println("No console available.");
                    System.exit(1);
                } else {
                    System.out.println("Enter password for account:");

                    char[] hiddenpassword = console.readPassword();
                    password = new String(hiddenpassword);
              
                    
                    if (passwordLen < 7){
                        System.out.println("WARANING: STRONG PASSWORDS SHOULD BE AT LEAST 7 CHARACTERS");
                    }
           

                }
                VaultPasswords.addPasswordAccount(service, user, password, col);
            }
    }
}
