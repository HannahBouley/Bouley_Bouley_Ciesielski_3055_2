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

    public static void main(String[] args) {
        // Load (unseal) the vault at startup
        Vault vault = new Vault();
        
        try {
            vault.loadVault();
        } catch (Exception e) {
            System.out.println("Error loading vault: " + e.getMessage());
            e.printStackTrace();
            return;
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

        // Placeholder: Command-line handling can be added here
        System.out.println("Vault loaded successfully. Add CLI functionality here.");
        

        // Display the help menu if no args are inputed 
        if (args.length < 1){

            System.out.println(Menu.DisplayMenuText());
           
        }
        


        handleCommandLineInputs(args);
    }

    /**
     * Handles commands from the command line interface
     * @param args
     */
    public static void handleCommandLineInputs(String[] args) {
        // An array of options
        LongOption[] argsList = new LongOption[3];

        argsList[0] = new LongOption("add", false, 'a');
        argsList[1] = new LongOption("service", true, 's');
        argsList[2] = new LongOption("user", true, 'u');

        // The current option being processed
        Tuple<Character, String> currOpt;

        // Set up a new parser to parse the options
        OptionParser parser = new OptionParser(args);
        parser.setOptString("as:u:");
        parser.setLongOpts(argsList);

        // Gets the next option in the command line args
        while (parser.getOptIdx() != args.length) {
            currOpt = parser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'a':

                    String service = currOpt.getSecond();

                    
                    break;

                case 's':

                    break;

                case 'u':

                    break;
                default:
                    break;
            }
        }
    }
}
