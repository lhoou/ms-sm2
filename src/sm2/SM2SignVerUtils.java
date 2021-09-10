package sm2;

import utils.Util;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;


import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Enumeration;

/**
 * 国密算法的签名、验签
 */
public class SM2SignVerUtils {
	/**
	 * 默认USERID
	 */
	public static String USER_ID = "1234567812345678";
	/**
	 * 私钥签名
	 * 使用SM3进行对明文数据计算一个摘要值
	 * @param privatekey 私钥
	 * @param sourceData 明文数据
	 * @return 签名后的值
	 * @throws Exception
	 */
	public static SM2SignVO Sign2SM2(byte[] privatekey,byte[] sourceData) throws Exception{
		SM2SignVO sm2SignVO = new SM2SignVO();
		sm2SignVO.setSm2_type("sign");
		SM2Factory factory = SM2Factory.getInstance();
		BigInteger userD = new  BigInteger(privatekey);
		//System.out.println("userD:"+userD.toString(16));
		sm2SignVO.setSm2_userd(userD.toString(16));

		ECPoint userKey = factory.ecc_point_g.multiply(userD);
		//System.out.println("椭圆曲线点X: "+ userKey.getXCoord().toBigInteger().toString(16));
		//System.out.println("椭圆曲线点Y: "+ userKey.getYCoord().toBigInteger().toString(16));
		
		
		SM3Digest sm3Digest = new SM3Digest();
		byte [] z = factory.sm2GetZ(USER_ID.getBytes(), userKey);
		//System.out.println("SM3摘要Z: " + Util.getHexString(z));
		//System.out.println("被加密数据的16进制: " + Util.getHexString(sourceData));
		sm2SignVO.setSm3_z(Util.getHexString(z));
		sm2SignVO.setSign_express(Util.getHexString(sourceData));

		sm3Digest.update(z, 0, z.length);
		sm3Digest.update(sourceData,0,sourceData.length);
		byte [] md = new byte[32];
		sm3Digest.doFinal(md, 0);
		//System.out.println("SM3摘要值: " + Util.getHexString(md));
		sm2SignVO.setSm3_digest(Util.getHexString(md));

		SM2Result sm2Result = new SM2Result();
		factory.sm2Sign(md, userD, userKey, sm2Result);
		//System.out.println("r: " + sm2Result.r.toString(16));
		//System.out.println("s: " + sm2Result.s.toString(16));
		sm2SignVO.setSign_r(sm2Result.r.toString(16));
		sm2SignVO.setSign_s(sm2Result.s.toString(16));
		sm2SignVO.setSign_k(sm2Result.keyra.toString());
		ASN1Integer d_r = new ASN1Integer(sm2Result.r);
		ASN1Integer d_s = new ASN1Integer(sm2Result.s);
		
		ASN1Integer d_x = new ASN1Integer(sm2Result.keyra.getXCoord().toBigInteger());
		ASN1Integer d_y = new ASN1Integer(sm2Result.keyra.getYCoord().toBigInteger());
		
		
		ASN1EncodableVector v2 = new ASN1EncodableVector();
		v2.add(d_r);
		v2.add(d_s);
		v2.add(d_x);
		v2.add(d_y);
	
		DERSequence sign = new DERSequence(v2);
		String result = Util.byteToHex(sign.getEncoded());
	
		
		
		sm2SignVO.setSm2_sign(result);
		return sm2SignVO;
	}
	
	
	public static void Sign2SM2single(int index, int partynum, BigInteger randomness, byte[] privateKey, String User_ID, byte[] randomList, byte[] keyList, byte[] sourceData, SM2Result singleResult) {
		
		//System.out.println(privateKey.length);
		SM2Factory factory = SM2Factory.getInstance();
		BigInteger userD = new  BigInteger(privateKey);
        ECPoint userKey = factory.ecc_point_g.multiply(userD);
        singleResult.randomK = randomList;
        ECPoint[] userKeyformat = new ECPoint[partynum];
        ECPoint[] randomFormat = new ECPoint[partynum];
        ECPoint pubKey = null;
       // System.out.println(keyList);
       // System.out.println(Util.byteToHex(userKey.getEncoded()));

        	for (int i=0,j=0; i< keyList.length; i=i+65,j++) {
        		byte[] formatedPub = new byte[65];
        		byte[] formatedRan = new byte[65];
        		System.arraycopy(keyList, i, formatedPub, 0, 65);
        		System.arraycopy(randomList, i, formatedRan, 0, 65);
        		SM2Factory fac = SM2Factory.getInstance();
        		ECPoint tempKey = fac.ecc_curve.decodePoint(formatedPub);
        		ECPoint tempRan = fac.ecc_curve.decodePoint(formatedRan);
        		userKeyformat[j] = tempKey;
        		randomFormat[j] = tempRan;
        		//System.out.println(Util.byteToHex(tempKey.getEncoded()));

    	}
       // 	System.out.println(index);
       // 	System.out.println(userKeyformat.length);
       // 	System.out.println(randomFormat.length);
       // 	System.out.println(Util.byteToHex(userKeyformat[index].getEncoded()));
      //  	System.out.println(Util.byteToHex(randomFormat[index].getEncoded()));
        	
       
//        if(userKey.equals(userKeyformat[index])) {
//        	System.out.println("Valid Key!"); //alert
//        }else {
//        	System.out.println("Invalid Keys!"); 
//        }
      
       pubKey = userKeyformat[0];
       pubKey = pubKey.add(randomFormat[0]);
       //System.out.println(Util.byteToHex(pubKey.getEncoded()));
        for (int i=1; i<partynum; i++) {
        	
        	pubKey = pubKey.add(userKeyformat[i]);
        	pubKey = pubKey.add(randomFormat[i]);
        }
        //check
        singleResult.randomK = randomList;
        singleResult.keyrb = pubKey;
        singleResult.partyNumber =partynum;
        //System.out.println(Util.byteToHex(pubKey.getEncoded()));
        
		SM3Digest sm3Digest = new SM3Digest();
		byte [] z = factory.sm2GetZ(User_ID.getBytes(), pubKey);
	
         
		sm3Digest.update(z, 0, z.length);
		sm3Digest.update(sourceData,0,sourceData.length);
		byte [] md = new byte[32];
		sm3Digest.doFinal(md, 0);
	
		singleResult.setSm3_digest(Util.getHexString(md));
	    
		byte[] bytes = User_ID.getBytes();
	    String encoded = Base64.getEncoder().encodeToString(bytes);
	    byte[] decoded = Base64.getDecoder().decode(encoded);
	    singleResult.userID = decoded;

	       
  
		factory.sm2singleSign(md, userD, userKey, randomness, singleResult);		

	}
	
	
	public static SM2SignVO Sign2MSSM2(SM2Result sm2result, byte[] privK) {
		SM2SignVO sm2sign = new SM2SignVO();
		sm2sign.setSm2_type("ms");
		
		//
//		int index = 0;
//		for (int i=0; i< sm2result.partyNumber; i++) {
//         
//  		byte[] lengthIndex = new byte[4];
//  		System.arraycopy(sm2result.userID, index, lengthIndex, 0, 4);
//  		index = index +4;
//  		int length = Util.byteToInt(lengthIndex);
//  		byte[] userid = new byte[length];
//  		System.arraycopy(sm2result.userID, index, userid, 0, length);
//  		index = index + length;
//  	    System.out.println(new String(userid));
//		}
		return sm2sign;
	}
	
	
	
	
	/**
	 * 验证签名
	 * @param publicKey 公钥信息
	 * @param sourceData 密文信息
	 * @param signData 签名信息
	 * @return 验签的对象 包含了相关参数和验签结果
	 */
	@SuppressWarnings("unchecked")
	public static SM2SignVO VerifySignSM2(byte[] publicKey,byte[] sourceData,byte[] signData){
		try {
			byte[] formatedPubKey;
			SM2SignVO verifyVo = new SM2SignVO();
			verifyVo.setSm2_type("verify");
			if (publicKey.length == 64) {
				// 添加一字节标识，用于ECPoint解析
				formatedPubKey = new byte[65];
				formatedPubKey[0] = 0x04;
				System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
			} else{
				formatedPubKey = publicKey;
			}
			SM2Factory factory = SM2Factory.getInstance();
			ECPoint userKey = factory.ecc_curve.decodePoint(formatedPubKey);

			SM3Digest sm3Digest = new SM3Digest();
			byte [] z = factory.sm2GetZ(USER_ID.getBytes(), userKey);
			//System.out.println("SM3摘要Z: " + Util.getHexString(z));
			verifyVo.setSm3_z(Util.getHexString(z));
			sm3Digest.update(z,0,z.length);
			sm3Digest.update(sourceData,0,sourceData.length);
			byte [] md = new byte[32];
			sm3Digest.doFinal(md, 0);
			//System.out.println("SM3摘要值: " + Util.getHexString(md));
			verifyVo.setSm3_digest(Util.getHexString(md));
			ByteArrayInputStream bis = new ByteArrayInputStream(signData);
			ASN1InputStream dis = new ASN1InputStream(bis);
			SM2Result sm2Result = null;
			ASN1Primitive derObj = dis.readObject();
			Enumeration<ASN1Integer> e = ((ASN1Sequence)derObj).getObjects();
			BigInteger r = ((ASN1Integer) e.nextElement()).getValue();
			BigInteger s = ((ASN1Integer) e.nextElement()).getValue();
	         
			BigInteger x = ((ASN1Integer) e.nextElement()).getValue();
			BigInteger y = ((ASN1Integer) e.nextElement()).getValue();
			ECPoint randomk = factory.ecc_curve.createPoint(x, y);
			
			
			sm2Result = new SM2Result();
			sm2Result.r = r;
			sm2Result.s = s;
			sm2Result.keyra = randomk;
			//System.out.println("vr: " + sm2Result.r.toString(16));
			//System.out.println("vs: " + sm2Result.s.toString(16));
			verifyVo.setVerify_r(sm2Result.r.toString(16));
			verifyVo.setVerify_s(sm2Result.s.toString(16));
			factory.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
			//boolean verifyFlag = sm2Result.r.equals(sm2Result.R);
			
			ECPoint x3y3 = factory.ecc_point_g.add(userKey);
			boolean verifyFlag = sm2Result.keyrb.equals(x3y3);
			verifyVo.setVerify(verifyFlag);
			return  verifyVo;
		} catch (IllegalArgumentException e) {
			return null;
		}catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static boolean VerifyMSSM2(byte[] publicKey, byte[] sourceData, SM2Result sm2result){
		
		int partynum = sm2result.partyNumber;
		ECPoint userKey = sm2result.keyrb;
		
		byte[] userIDList = sm2result.userID;
		String User_ID;

		try {

			
			SM2Factory factory = SM2Factory.getInstance();

	        byte[] mdlist = new byte[partynum*32];

	        int index = 0;
	        
           for (int i=0; i< partynum; i++) {
             
      		byte[] lengthIndex = new byte[4];
      		System.arraycopy(userIDList, index, lengthIndex, 0, 4);
      		index = index +4;
      		int length = Util.byteToInt(lengthIndex);
      		byte[] userid = new byte[length];
      		System.arraycopy(userIDList, index, userid, 0, length);
      		index = index + length;
      	    //System.out.println(new String(userid));
      	    
      	    SM3Digest sm3Digest = new SM3Digest();
      	    
      	    //For Simplification, using userKey
			byte [] z = factory.sm2GetZ(new String(userid).getBytes(), userKey);
		
			sm3Digest.update(z,0,z.length);
			sm3Digest.update(sourceData,0,sourceData.length);
			byte [] md = new byte[32];
			sm3Digest.doFinal(md, 0);
			
			//System.out.println(Util.byteToHex(md));
			System.arraycopy(md, 0, mdlist, i*32, 32);
  	       }
	       
          factory.sm2msVrfy(mdlist, publicKey, sm2result);
			

			//factory.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
			//boolean verifyFlag = sm2Result.r.equals(sm2Result.R);
			
			ECPoint verify = sm2result.verify1;
			boolean verifyFlag = sm2result.verify2.equals(verify);
			//verifyVo.setVerify(verifyFlag);
			return  verifyFlag;
		} catch (IllegalArgumentException e) {
			return false;
		}catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	
	
	
	

}
