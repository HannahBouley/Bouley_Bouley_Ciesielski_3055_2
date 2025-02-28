public class Menu {
    
    /**
     * Displays the menu and list of avaiable options
     * @return
     */
    public static String DisplayMenuText(){

        String menuTitle = "--WELCOME-TO-THE-SECURE-VAULT--\n";

        String options = 
        "vault --add --service <name> --user <uname> \n" + 
        "vault --add --service <name> --user <uname> --gen <len> \n" +
        "vault --add --service <name> --key <key> \n" +
        "vault --add --service <name> --keygen\n" +
        "vault --lookup-pass <name>\n" +
        "vault --lookup-key <name>" ;

        String menuPrompt = menuTitle + options;

        return menuPrompt;
    }


}
