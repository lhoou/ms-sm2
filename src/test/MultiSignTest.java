package test;


import sm2.SM2KeyVO;
import sm2.SM2Result;
import sm2.SM2SignVO;
import sm2.SM2SignVerUtils;
import utils.Util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.math.ec.ECPoint;

import sm2.SM2EncDecUtils;
import sm2.SM2Factory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.UUID;

public class MultiSignTest {
    //SM2公钥编码格式
    //HardPubKey:3059301306072A8648CE3D020106082A811CCF5501822D03420004+X+Y
    //SoftPubKey:04+X+Y
    public static final String SM2PubHardKeyHead = "3059301306072A8648CE3D020106082A811CCF5501822D034200";

    public static void main(String[] args) throws Exception {
    	System.out.println("Please Enter the Number of Parties:\n");
    	Scanner input=new Scanner(System.in);
    	int partyNum=input.nextInt();
    	if (partyNum<=0) {
    		System.out.println("\nPlease Re-Enter a Valid Number:");
    	}
    	else {
    		System.out.println("\nKey Generation for " + partyNum+ " Parties:\n");
    	}
    	
    	SM2KeyVO[] sm2KeyVO = new SM2KeyVO[partyNum]; 
    	String[]  userID = new String[partyNum];
    	byte[] pubKeyList =  new byte[65*partyNum];  // public key list in byte
    	byte[] priKeyList = new byte[32*partyNum];
    	int id_length = 0;
    	
    	
    	//pubKeyList and priKeyList
    	for (int i=0; i < partyNum; i++) {
    		System.out.println("Please Input a UserID for Party "+(i+1));
    		Scanner sc=new Scanner(System.in);
    		userID[i]=sc.next();
   
    		sm2KeyVO[i] = new SM2KeyVO();
    		
    		sm2KeyVO[i] = generateSM2Key();
    		
    		System.out.println("User"+(i+1)+":"+userID[i]+"\n Public key:" + sm2KeyVO[i].getPubHexInSoft());
    		System.arraycopy(sm2KeyVO[i].getPub(), 0, pubKeyList, 65*i, 65);
            System.out.println(" Private Key:" + sm2KeyVO[i].getPriHexInSoft()+"\n");
            System.arraycopy(sm2KeyVO[i].getPrivateKey().toByteArray(), 0, priKeyList, 32*i, 32);
    	}
    

    // System.out.println(sm2KeyVO[1].getPrivateKey().toByteArray().length);
    	
    	//test
//    	for (int i=0; i< pubKeyList.length; i=i+65) {
//    		byte[] formatedPub = new byte[65];
//    		System.arraycopy(pubKeyList, i, formatedPub, 0, 65);
//    		SM2Factory fac = SM2Factory.getInstance();
//    		ECPoint userKey = fac.ecc_curve.decodePoint(formatedPub);
//    		System.out.println(Util.byteToHex(userKey.getEncoded()));
//    	}

//    	for (int i=0; i< priKeyList.length; i=i+32) {
//    		byte[] formatedPri = new byte[32];
//    		System.arraycopy(priKeyList, i, formatedPri, 0, 32);
//    		BigInteger userD = new  BigInteger(formatedPri);
//    		System.out.println(Util.byteToHex(userD.toByteArray()));
//    	}

        System.out.println("\nSining Process:\n");
        String src = "Traffic Jam!";
        System.out.println("\nThe message to co-sign is:"+ src);
        System.out.println("MessageInHex:" + Util.byteToHex(src.getBytes())+"\n");
        String s5 = Util.byteToHex(src.getBytes());
        
           
     //  SM2SignVO sign = genSM2Signature(sm2KeyVO[1].getPriHexInSoft(), s5);
       SM2Result[] singles = new SM2Result[partyNum];
     
       //System.out.println("\nThe randomness:\n");
       SM2Factory factory = SM2Factory.getInstance();
       byte[] randomList =  new byte[65*partyNum];
       BigInteger[] randomk = new BigInteger[partyNum];
       BigInteger rand=null;
       
       
       //create randomlist
       for (int i=0; i < singles.length; i++) {
    	  SM2Result temp = new SM2Result();
    	  rand = factory.sm2Random(temp);
          //System.out.println(Util.byteToHex(temp.keyra.getEncoded()));
          singles[i] = temp;
          randomk[i] = rand;
          System.out.println("Randomness Chosen by Party"+(i+1)+":\n"+Util.byteToHex(singles[i].keyra.getEncoded()));
          System.out.println(randomk[i]+"\n");
          System.arraycopy(singles[i].keyra.getEncoded(), 0, randomList, 65*i, 65);
    	}
        
   	//test
//   	for (int i=0; i< randomList.length; i=i+65) {
//   		byte[] formatedPub = new byte[65];
//   		System.arraycopy(randomList, i, formatedPub, 0, 65);
//   		SM2Factory fac = SM2Factory.getInstance();
//   		ECPoint userKey = fac.ecc_curve.decodePoint(formatedPub);
//   		System.out.println(Util.byteToHex(userKey.getEncoded()));
//   	}

       
       for (int i=0; i < partyNum; i++) {
    	long startTime1 = System.nanoTime();
    	genSM2Single(i, partyNum, randomk[i], sm2KeyVO[i].getPriHexInSoft(), userID[i], randomList, pubKeyList, s5, singles[i]);
    	long endTime1 = System.nanoTime(); 
		System.out.println("Local signing time for user "+ userID[i] + " : "+ (endTime1 - startTime1) + "ns\n");
    	id_length = id_length+singles[i].userID.length;
    	
       
    	//test
    		
    		//System.out.println(Util.byteToHex(singles[i].keyrb.getEncoded()));
        	//System.out.println(singles[i].s_i);
        	//System.out.println(singles[i].randomK);
        	//System.out.println(singles[i].sm3_digest);
        	//System.out.println(singles[i].r);
    	 //System.out.println(singles[i].userID.length); 
    	 //System.out.println(id_length);
    	 //System.out.println(singles[i].partyNumber);
    	// System.out.println(new String(singles[i].userID));
 
    	
    }

       //creat userIDList
          byte[] userIDList = new byte[id_length+4*partyNum];
          int tmp =0;
          for (int i=0; i<partyNum; i++) {
          System.arraycopy(Util.intToBytes(singles[i].userID.length), 0, userIDList, tmp, 4);
          tmp = tmp+4;
          System.arraycopy(singles[i].userID, 0, userIDList, tmp, singles[i].userID.length);
          tmp = tmp + singles[i].userID.length;
          }
          
          //test
//          int index = 0;
//          for (int i=0; i< partyNum; i++) {
//             
//      		byte[] lengthIndex = new byte[4];
//      		System.arraycopy(userIDList, index, lengthIndex, 0, 4);
//      		index = index +4;
//      		int length = Util.byteToInt(lengthIndex);
//      		byte[] userid = new byte[length];
//      		System.arraycopy(userIDList, index, userid, 0, length);
//      		index = index + length;
//      	    System.out.println(new String(userid));
//
//  	}
       
       
       //This should be a MPC protocol in real world. Here is only a simplified version.
      
       for (int i=1; i < partyNum; i++) {
       	singles[0].s_i = singles[0].s_i.add(singles[i].s_i);
       	
       }
       singles[0].userID = userIDList;
       SM2Factory ms2 = SM2Factory.getInstance();
       ms2.sm2ms(singles[0], priKeyList); 
       
  
		
		
		
       //Encoding
       ASN1Integer d_s = new ASN1Integer(singles[0].s);
	   ASN1Integer d_K = new ASN1Integer(singles[0].randomK);
		ASN1EncodableVector vs = new ASN1EncodableVector();
		vs.add(d_s);
		vs.add(d_K);
		DERSequence sign = new DERSequence(vs);
		String result = Util.byteToHex(sign.getEncoded());
		singles[0].setSm2_ms(result);
		System.out.println("\nThe Multi-signature is:\n" + singles[0].getSm2_ms());
       
       //SM2SignVO sign = genMSSM2(singles[0], priKeyList); 
        
        
     //System.out.println("\nThe Signature is:\n" + "s:"+singles[0].s);
        
        
        
        System.out.println("\nVerification Process:\n");
        
        
        //For simplification, we omitted the decoding process
       boolean b = verifyMSSM2(pubKeyList, s5, singles[0]);
       //boolean b = verifySM2Signature(sm2KeyVO[1].getPubHexInSoft(), s5, sign.getSm2_signForSoft());
//        boolean b = verifyMSSM2(pubKeyList, partyNum, s5, sign.getSm2_signForSoft());
        System.out.println("Is the multi-signature Valid:\n" + b);
        if (!b) {
            throw new RuntimeException();
        }


    }
    //产生非对称秘钥
    public static SM2KeyVO generateSM2Key() throws IOException {
        SM2KeyVO sm2KeyVO = SM2EncDecUtils.generateKeyPair();
        return sm2KeyVO;
    }
    //SM2公钥soft和Hard转换
    public static String SM2PubKeySoftToHard(String softKey) {
        return SM2PubHardKeyHead + softKey;
    }

    //SM2公钥Hard和soft转换
    public static String SM2PubKeyHardToSoft(String hardKey) {
        return hardKey.replaceFirst(SM2PubHardKeyHead, "");
    }


    //私钥签名,参数二:原串必须是hex!!!!因为是直接用于计算签名的,可能是SM3串,也可能是普通串转Hex
    public static SM2SignVO genSM2Signature(String priKey, String sourceData) throws Exception {
        SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexToByte(priKey), Util.hexToByte(sourceData));
        return sign;
    }
    
    public static void genSM2Single(int index, int totalNumber, BigInteger randomness, String priKey, String userid, byte[] random, byte[] keyList, String sourceData, SM2Result result) throws Exception {
    	SM2SignVerUtils.Sign2SM2single(index, totalNumber, randomness, Util.hexToByte(priKey), userid, random, keyList, Util.hexToByte(sourceData),result);
 
    }

    
    public static SM2SignVO genMSSM2(SM2Result result, byte[] privlist)throws Exception {
    	SM2SignVO sign = SM2SignVerUtils.Sign2MSSM2(result, privlist);
    	return sign;
    }
    
    
    //Verification
    public static boolean verifySM2Signature(String pubKey, String sourceData, String hardSign) {
    	System.out.println(Util.hexStringToBytes(pubKey));
    	System.out.println(Util.hexStringToBytes(pubKey).length);
        SM2SignVO verify = SM2SignVerUtils.VerifySignSM2(Util.hexStringToBytes(pubKey), Util.hexToByte(sourceData), Util.hexToByte(hardSign));
        return verify.isVerify();
    }

    public static boolean verifyMSSM2(byte[] pubkeylist, String sourcedata, SM2Result result) {
    	boolean vrfy = SM2SignVerUtils.VerifyMSSM2(pubkeylist, Util.hexToByte(sourcedata), result);
    	return vrfy;
    }



}
