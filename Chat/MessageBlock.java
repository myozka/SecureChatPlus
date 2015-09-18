package Chat;

import java.io.Serializable;

public class MessageBlock implements Serializable {
	String username;
	String message;
	Integer timestamp;
	Integer sequenceNo;

	MessageBlock(String username,String message,Integer timestamp,Integer sequenceNo){
		this.username = username;
		this.message = message;
		this.timestamp = timestamp;
		this.sequenceNo = sequenceNo;
	}
}