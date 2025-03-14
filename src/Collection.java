import java.io.File;
import java.io.InvalidObjectException;
import java.io.Serializable;
import java.util.HashMap;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

public class Collection implements JSONSerializable{

    private HashMap<String, String> keyData; // Key value keyDatas
    private String salt;
    private String vaultKey;
    private String iv;
    private String key;

    // For user password and service
    private String user = null;
    private String pass = null;
    private String useriv = null;
    private String service = null;

    /**
     * Creates new collection with a simple hash map
     */
    public Collection(){
        this.keyData = new HashMap<>();
   
    }

    /**
     * Gets the collection in serialized format and converts it into a deserialized form
     * @param obj
     * @throws InvalidObjectException
     */
    public Collection(JSONObject obj) throws InvalidObjectException {
        this.keyData = new HashMap<>();
        deserialize(obj);

    }

    public HashMap<String, String> getAllData(){
  
        return this.keyData;
    }

    	/**
	 * Serializes the object into a JSON encoded string.
	 * 
	 * @return a string representing the JSON form of the object.
	 */
	public String serialize() {
		return toJSONType().getFormattedJSON();
	}

    	/**
	 * Converts the object to a JSON type.
	 * 
	 * @return a JSON type either JSONObject or JSONArray.
	 */
	public JSONType toJSONType() {
		JSONObject obj = new JSONObject(); // Main obj
        JSONObject keyObj = new JSONObject(); // Vault key atributes
        JSONObject userObj = new JSONObject();
        JSONArray passwordArry = new JSONArray();
        JSONArray privateKeys = new JSONArray();

        // Vault key
        keyObj.put("iv", iv);
        keyObj.put("key", key);

        // Salt
		obj.put("salt", salt);
        obj.put("vaultKey", keyObj);

        if (useriv != null && service != null && user != null && pass != null){
            userObj.put("iv", " ");
            userObj.put("service", " ");
            userObj.put("user", " ");
            userObj.put("pass", " ");
        } else {
            userObj.put("iv", useriv);
            userObj.put("service", service);
            userObj.put("user", user);
            userObj.put("pass", pass);
        }
 
       
        passwordArry.add(userObj);
        obj.put("passwords", passwordArry);
    
        obj.put("privKeys", privateKeys);
        
	
		return obj;
	}


    public void addSaltValue(String salt){
        this.salt = salt;
    }

    public String getSaltValue(String s){
        return keyData.get(s);
    }

    public void addVaultKey(String vaultKey){
        this.vaultKey = vaultKey;
    }

    public void addKey(String key){
        this.key = key;
    }   

    public void addIv(String iv){
        this.iv = iv;
    }

    public void addData(String key, JSONType value){
        
        JSONArray block;

        if (value instanceof JSONArray){

            block = (JSONArray) value;

            // Put the objects from the array into the array list
            for (int i = 0; i < block.size(); i++){
                keyData.put(block.getString(i), block.getObject(i).toString());
            }
        }

    }

    public boolean containsKey(String key){
        return keyData.get(key) != null;
    }

    public JSONArray getArray(String arry){
        return JsonIO.readArray(arry);
    }

    public String getKeyData(String k){

        return keyData.get(k);
    }

    public String getIvData(String iv){
        
        return keyData.get(iv);
    }


    public void addPasswordData(JSONObject passwordData){
        

        this.user = passwordData.getString("user");
        this.iv = passwordData.getString("iv");
        this.service = passwordData.getString("service");
        this.pass = passwordData.getString("pass");
    
    }
    

    /**
     * Derserializes a JSON object into a readable form
     * @param obj
     * @throws InvalidObjectException
     */
    public void deserialize(JSONType obj) throws InvalidObjectException {
        JSONObject tmp;
        JSONObject vk;
        JSONArray passwordsArry;

        if(obj instanceof JSONObject){
            tmp = (JSONObject) obj;

            if (tmp.containsKey("vaultKey")){
                
                vk = tmp.getObject("vaultKey");

                keyData.put("iv", vk.getString("iv"));
                keyData.put("key", vk.getString("key"));
            }

            if (tmp.containsKey("passwords")){
             
                passwordsArry = tmp.getArray("passwords");

                for (int i = 0; i < passwordsArry.size(); i++){

                    if (passwordsArry.getObject(i).containsKey("iv")){
                        keyData.put("useriv", passwordsArry.getString(i));
                    } else if (passwordsArry.getObject(i).containsKey("service")){
                        keyData.put("service", passwordsArry.getString(i));
                    } else if (passwordsArry.getObject(i).containsKey("user")){
                        keyData.put("user", passwordsArry.getString(i));
                    } else if (passwordsArry.getObject(i).containsKey("pass")){
                        keyData.put("pass", passwordsArry.getString(i));
                    }
                }
            }
        }

    
    }
}
