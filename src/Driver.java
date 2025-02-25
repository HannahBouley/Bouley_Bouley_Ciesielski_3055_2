import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import merrimackutil.json.types.JSONArray;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.parser.JSONParser;

class Driver{

    private static final String VAULT_JSON_PATH = "vault.json";

    private static File vaultFile = new File(VAULT_JSON_PATH);

    public static void main(String[] args) {
        
        // Set up the vault
        initilizeJsonDataBase();
        
    }

    /**
     * Creates new JSON Database or loads an existing database
     */
    public static void initilizeJsonDataBase(){

        try {
            JSONObject root;

            if (vaultFile.exists()){
                root = JsonIO.readObject(vaultFile);
                System.out.println("Loaded exisiting valut");
            } else {
                System.out.println("Creating a new JSON database");
                root = new JSONObject();

                writeSerializedObject(root, vaultFile);
            }
        } catch (Exception e) {
            System.out.println("There was an error initilizing the databse " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Creates the new json file
     * @param obj
     * @param jsonFile
     * @throws FileNotFoundException
     */
    private static void writeSerializedObject(JSONObject obj, File jsonFile) throws FileNotFoundException {
        try (PrintWriter out = new PrintWriter(jsonFile)) {
            out.println(obj.toJSON());
        }
    }

    /**
     * Handles commands from the command line interface
     * @param args
     */
    public static void handleCommandLineInputs(String[] args){

        // An array of options
        LongOption[] argsList = new LongOption[8];

        // The operations

        // The current option being processed
        Tuple<Character, String> currOpt;

        // Set up a new parser to pase the options
        OptionParser paser = new OptionParser(args);
        paser.setOptString(null);
        paser.setLongOpts(argsList);

        // Gets the next option in the command line args
        while(paser.getOptIdx() != args.length){
         
            currOpt = paser.getLongOpt(false);

            switch (paser) {
                case null:
                    
                    break;
            
                default:
                    break;
            }
        }


    }
}