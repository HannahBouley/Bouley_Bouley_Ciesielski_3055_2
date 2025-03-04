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

    private HashMap<String, JSONType> pair; // Key value pairs
    private String salt;
    private String vaultKey;
    private String iv;
    private String key;

    /**
     * Creates new collection with a simple hash map
     */
    public Collection(){
        this.pair = new HashMap<>();
   
    }

    /**
     * Gets the collection in serialized format and converts it into a deserialized form
     * @param obj
     * @throws InvalidObjectException
     */
    public Collection(JSONObject obj) throws InvalidObjectException {
        this.pair = new HashMap<>();
        deserialize(obj);

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
        JSONArray passwordArry = new JSONArray();
        JSONArray privateKeys = new JSONArray();

        // Vault key
        keyObj.put("iv", iv);
        keyObj.put("key", key);

        // Salt
		obj.put("salt", salt);
        obj.put("vaultKey", keyObj);

        obj.put("passwords", passwordArry);
        obj.put("privKeys", privateKeys);
        
	
		return obj;
	}


    public void addSaltValue(String salt){
        this.salt = salt;
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

    }

    public boolean containsKey(String key){
        return pair.get(key) != null;
    }

    public JSONArray getArray(String arry){
        return JsonIO.readArray(arry);
    }

    public JSONObject getData(String k){
        return (JSONObject) pair.get(k);
    }

    public void deserialize(JSONType obj) throws InvalidObjectException {
        JSONObject tmp;
        JSONObject key;
        JSONArray block = null;
  
        if (obj instanceof JSONObject)
        {
          tmp = (JSONObject) obj;


        // Get the passwords array in the json file
        if (tmp.containsKey("passwords")){

            block = tmp.getArray("passwords");

                
        pair.clear();
        for (int i = 0; i < block.size(); i++)
            pair.put(block.getObject(i).getString("user"), block.getObject(i));
        }
              
        else if (tmp.get("vaultKey") != null){
      
            key = tmp.getObject("key");

            pair.clear();
            pair.put("key", key);
            

        }
        
    
          else 
            throw new InvalidObjectException("Expected a PubKeyRing object -- keys expected.");
        }
        else 
          throw new InvalidObjectException("Expected a PubKeyRing object -- recieved array");
  
     
     }

    
}
