import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This program is implemented to read the set of packets and displays
 * detailed summary for those packets.
 * 
 * First, it displays the ethernet header fields of the captured frames.
 * Second, if the ethernet frame contains an IP datagram, it prints the IP header.
 * Third, it prints the packets encapsulated in the IP datagram. 
 * Packets encapsulated could be ICMP,TCP,or UDP.
 * 
 * @author gaurav gaur(gxg7435@rit.edu)
 *
 */
public class pktanalyzer {
	
	/**
	 * This is the main function of the program that is used 
	 * to analyze the contents from the file.
	 * 
	 * @param args[0] : filename of the packet to be analyzed.
	 */
	
	public static void main(String[] args) {
		
		pktanalyzer pkt = new pktanalyzer(); 
		File file = new File(args[0]);
		
		byte[] contentInBytes = new byte[(int) file.length()];
		String packetData = null;
		
		try {
			FileInputStream fis = new FileInputStream(file);
			fis.read(contentInBytes);
			
			packetData = javax.xml.bind.DatatypeConverter.printHexBinary(contentInBytes);
			pkt.ethernetContent(packetData);
			int val = pkt.ipContent(packetData);
			
			if(val == 1) {
				pkt.icmpContent(packetData);
			}
			
			else if(val == 6) {
				pkt.tcpContent(packetData);
			}
			
			else if(val == 17) {
				pkt.udpContent(packetData);
			}
		} 
		
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * This procedure is implemented to capture IP header information
	 * from the packet.
	 * 
	 * @param packetData: packet content read from the file.
	 * @return protocol id to determine what packet is encapsulated.
	 */
	public int ipContent(String packetData) {
		
		print("IP:  ----- IP Header ----- ");
		print("IP: ");
		
		print("IP: Version = " +getSubString(packetData,28, 29));
		int hlen = Integer.parseInt(getSubString(packetData,29,30),16);
		
		print("IP: Header Length = " +(hlen*4) + " bytes");
		print("IP: Type of Service = 0x" +getSubString(packetData,30,32));
		
		int tmp = Integer.parseInt(getSubString(packetData,30,32) , 16);
		byte serv = (byte) tmp;
		
		print("IP: xxx. .... = 0 (precedence)");
		print("IP: ..." + serv +".... = normal delay");
		
		print("IP: ...." + serv +"... = normal throughput");
		print("IP: ....." + serv +"... = normal reliability");
		
		print("IP: Total Length = " +Integer.parseInt(getSubString(packetData,32,36),16) + " bytes");
		print("IP: Identification = " +Integer.parseInt(getSubString(packetData,36,40),16));
		
		print("IP: Flags = " +getSubString(packetData,40,44));
		int flagInt = Integer.parseInt(getSubString(packetData,40,42),16);
		
		String flagStr = ""+Integer.toBinaryString(flagInt);
		String fragVal = getSubString(flagStr,0,1);
		
		if(fragVal.equals("1")) {
			print("IP: .1.. .... = do not fragment ");
		}
		else {
			print("IP: .0.. .... = fragment ");
		}
		
		char[] fragArr = flagStr.toCharArray();
		
		if(fragArr[0] == '1') {
			print("IP: .1.. .... = not last fragment ");
		}
		else {
			print("IP: ..0. .... = last fragment ");
		}
		
		print("IP: Fragment offset : "+Integer.parseInt(getSubString(packetData,42,44),16)+ " bytes");
		print("IP: Time to live = " +Integer.parseInt(getSubString(packetData,44,46),16) + " seconds/hops");
		
		String id_protocol = getSubString(packetData,46,48);
		if(id_protocol.equals("01")) {
			print("IP: Protocol = " +Integer.parseInt(getSubString(packetData,46,48),16)+ " (ICMP)");
		}
		
		else if(id_protocol.equals("06")) {
			print("IP: Protocol = " +Integer.parseInt(getSubString(packetData,46,48),16)+" (TCP)");
		}
		
		else {
			print("IP: Protocol = " +Integer.parseInt(getSubString(packetData,46,48),16)+ " (UDP)");
		}
		
		print("IP: Header Checksum = " +getSubString(packetData,48,52));
		
		fetchAddr(packetData,52,60,"Source");
		fetchAddr(packetData,60,68,"Destination");
		
		print("IP: No Options ");
		print("IP: ");
				
		int protocolVal = Integer.parseInt(id_protocol,16);
		return protocolVal;
	}
	
	/**
	 * This procedure is implemented to fetch the source and destination ip address.
	 * 
	 * @param packetData : packet content from the file
	 * @param start : to identify the start value of data byte in packet to fetch ip address.
	 * @param last : to identify the last value of data byte.
	 * @param id : to identify whether it is source or destination.
	 */
	public void fetchAddr(String packetData,int start,int last,String id) {
		
		int class1,class2,class3,class4;
		String val = getSubString(packetData,start,last) ;
		
		class1 = Integer.parseInt(getSubString(val,0, 2),16);
		class2 = Integer.parseInt(getSubString(val,2, 4),16);
		
		class3 = Integer.parseInt(getSubString(val,4, 6),16);
		class4 = Integer.parseInt(getSubString(val,6, 8),16);
		
		String appendVal = class1+"."+class2+"."+class3+"."+class4;	
		InetAddress ip;
		
		try {
			ip = InetAddress.getByName(appendVal);
			String hostName = ip.getHostName();
			print("IP: "+id+" Address = " + appendVal +", "+hostName);
		} 
		
		catch (UnknownHostException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * This procedure is implemented to fetch the information
	 * regarding icmp packet.
	 * 
	 * @param packetData: packet content read from file.
	 */
	public void icmpContent(String packetData) {
		
		print("ICMP:  ----- ICMP Header ----- ");
		print("ICMP: ");
		
		print("ICMP:  Type " +Integer.parseInt(getSubString(packetData,68, 70)));
		print("ICMP:  Code " +Integer.parseInt(getSubString(packetData,70, 72)));
		
		print("ICMP:  Checksum " +getSubString(packetData,72, 76));
		print("ICMP: ");
		
	}

	/**
	 * This procedure is implemented to fetch the information
	 * regarding udp packet.
	 * 
	 * @param packetData: packet content read from file.
	 */
	public void udpContent(String packetData) {
		
		print("UDP:  ----- UDP Header ----- ");
		print("UDP: ");
		
		print("UDP:  Source Port Number " +Integer.parseInt(getSubString(packetData,68, 72),16) );
		print("UDP:  Destination Port Number " +Integer.parseInt(getSubString(packetData,72, 76),16) );
		
		print("UDP:  Length " +Integer.parseInt(getSubString(packetData,76, 80),16));
		print("UDP:  Checksum " +getSubString(packetData,80, 84));
		
		print("UDP: ");
		print("UDP: Data: (First 64 Bytes)");
		
		print("UDP: Data " +getSubString(packetData,84, 88) + " " +getSubString(packetData,88, 92) +
		" " + getSubString(packetData,92, 96) + " " + getSubString(packetData,96, 100));
		
		print("UDP: Data " +getSubString(packetData,100, 104) + " " +getSubString(packetData,104, 108) +
		" " + getSubString(packetData,108, 112) + " " + getSubString(packetData,112, 116));
		
		print("UDP: Data " +getSubString(packetData,116, 120) + " " +getSubString(packetData,120, 124) +
		" " + getSubString(packetData,124, 128) + " " + getSubString(packetData,128, 132));
		
		print("UDP: Data " +getSubString(packetData,132, 136) + " " +getSubString(packetData,136, 140) +
		" " + getSubString(packetData,140, 144) + " " + getSubString(packetData,144, 148));
	
	}

	/**
	 * This procedure is implemented to fetch the information
	 * regarding TCP packets.
	 * 
	 * @param packetData : packet content read from the file.
	 */
	public void tcpContent(String packetData) {
		
		print("TCP: ---TCP Header");
		print("TCP:");
		
		print("TCP: Source Port = "+Integer.parseInt(getSubString(packetData, 68, 72),16));
		print("TCP: Destination Port = "+Integer.parseInt(getSubString(packetData, 72, 76),16));
		
		print("TCP: Sequence Number = "+Long.parseLong(getSubString(packetData, 76, 84),16)); 
		print("TCP: Acknowledgement Number ="+Long.parseLong(getSubString(packetData, 84, 92),16));
		
		print("TCP: Data offset = "+ (Integer.parseInt(getSubString(packetData, 92, 93),16)*4)+" bytes");
		print("TCP: Flags = 0x"+getSubString(packetData, 94, 96));
		
		int flagValInt = (Integer.parseInt(getSubString(packetData, 94, 96),16));
		String flagValStr = Integer.toBinaryString(flagValInt);
		String extraZero = "";
		
		int len = flagValStr.length();
		int diff = 6 - len;
		
		if(diff == 0) {
			print("");
		}
		
		else {
			for(int i=0; i<len;i++) {
				extraZero = extraZero + "0";
			}
			flagValStr = extraZero + flagValStr;
		}
		
		print("TCP: .."+ getSubString(flagValStr, 0, 1)+"..... = No urgent pointer");
		print("TCP: .."+ getSubString(flagValStr, 1, 2)+".... = Acknowledgement");
		
		print("TCP: .."+ getSubString(flagValStr, 2, 3)+"... = Push");
		print("TCP: .."+ getSubString(flagValStr, 3, 4)+".. = No Reset");
		
		print("TCP: .."+ getSubString(flagValStr, 4, 5)+". = No Syn");
		print("TCP: .."+ getSubString(flagValStr, 5, 6)+" = No Fin");
		
		print("TCP: Window : " +Integer.parseInt(getSubString(packetData,96, 100),16));
		print("TCP: Checksum :0x" +getSubString(packetData, 100, 104));
		
		print("TCP: Urgent Pointer :" +Integer.parseInt(getSubString(packetData,104, 108),16));
		print("TCP: ");
		
		print("TCP: Data: (First 64 bytes) ");
		print("TCP: Data " +getSubString(packetData,108, 112) + " " + getSubString(packetData,112,116) +
		" " + getSubString(packetData,116, 120) + " " + getSubString(packetData,120, 124));
		
		print("TCP: Data " +getSubString(packetData,124, 128) + " " +getSubString(packetData,128, 132) +
		" " + getSubString(packetData,132, 136) + " " + getSubString(packetData,136, 140));
		print("TCP: Data " +getSubString(packetData,140, 144) + " " +getSubString(packetData,144, 148) +
		" " + getSubString(packetData,148, 152) + " " + getSubString(packetData,152, 156));
		
		print("TCP: Data " +getSubString(packetData,156, 160) + " " +getSubString(packetData,160, 164) +
		" " + getSubString(packetData,164, 168) + " " + getSubString(packetData,168, 172));
	}
	
	/**
	 * This procedure is implemented to print the argument 
	 * passed to it.
	 * 
	 * @param message: data that needs to be displayed.
	 */
	public void print(String message) {
		System.out.println(message);
	}
	
	/**
	 * This procedure is implemented to get the substring from 
	 * the string that represents the packet content.
	 * 
	 * @param val: input String
	 * @param start : start index of substring
	 * @param end : last index of substring
	 * @return : final substring
	 */
	public String getSubString(String val,int start,int end) {
		
		return val.substring(start, end);
	}
	
	/**
	 * This procedure is implemented to fetch the information
	 * regarding ethernet headers.
	 * 
	 * @param packetData : the packet content read from the file.
	 */
	public void ethernetContent(String packetData) {
		
		print("ETHER:---Ether Header---");
		print("ETHER:");
		print("ETHER: Packet Size = "+(packetData.length()/2)+" bytes");
		
		print("ETHER: Destination = "+getSubString(packetData,0,2)+":"+getSubString(packetData,2,4)+":"+
		getSubString(packetData,4,6)+":"+getSubString(packetData,6,8)+":"+getSubString(packetData,8,10)+":"+
		getSubString(packetData,10,12));
		
		print("ETHER: Source = "+getSubString(packetData, 12, 14)+":"+getSubString(packetData, 14, 16)+":"+
		getSubString(packetData, 16, 18)+":"+getSubString(packetData, 18, 20)+":"+getSubString(packetData, 20, 22)+":"+
		getSubString(packetData, 22, 24));
		
		int val = checkEthertype(packetData,24,26);
		String ethtype= "";
		if(val == 8) {
			ethtype = getSubString(packetData, 24, 28) + "(IP)";
		}
		
		else {
			ethtype = getSubString(packetData, 24, 28);
		}
		
		print("ETHER: Ethertype = "+ethtype);
		print("ETHER:");
	}

	/**
	 * This procedure is implemented to fetch the ethernet type from
	 * the packet content that is being read from the file.
	 * 
	 * @param packetData : packet content read from the file
	 * @param start : start index of data byte.
	 * @param end : last index of data byte.
	 * @return : ethernet type.
	 */
	public int checkEthertype(String packetData,int start,int end) {
		int val = Integer.parseInt(getSubString(packetData, start, end));
		return val;
	}

}
