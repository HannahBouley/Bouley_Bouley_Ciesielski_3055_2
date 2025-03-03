import java.io.File;
import java.io.InvalidObjectException;
import java.io.Serializable;
import java.util.HashMap;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

public class Collection implements JSONSerializable{

    private HashMap<String, String> pair; // Key value pairs
    private String salt;
    private String vaultKey;
    private String iv;
    private String key;

    public Collection(){
        this.pair = new HashMap<>();
   
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
		JSONObject obj = new JSONObject();
        JSONObject keyObj = new JSONObject();

        keyObj.put("iv", iv);
        keyObj.put("key", key);

		obj.put("salt", salt);
        obj.put("vaultKey", keyObj);
	
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


    @Override
    public void deserialize(JSONType arg0) throws InvalidObjectException {
     
        throw new UnsupportedOperationException("Unimplemented method 'deserialize'");
    }


}