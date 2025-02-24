import java.lang.classfile.ClassFile.Option;
import java.util.function.LongUnaryOperator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import merrimackutil.json.types.JSONArray;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.parser.JSONParser;

class Driver{

    public static void main(String[] args) {
        
        
    }

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