package sm2;

import utils.Util;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;


public class SM2Factory {
	/*-----------------------国密算法相关参数begin-----------
	 * ------------------*/
	//A 第一系数
	private static final BigInteger a  = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",16);
	//B 第二系数
	private static final BigInteger b  = new BigInteger("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",16);
	//曲线X系数
	private static final BigInteger gx = new BigInteger("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",16);
	//曲线Y系数
	private static final BigInteger gy = new BigInteger("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",16);
	//生产者顺序系数
	private static final BigInteger n  = new BigInteger("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",16);
	//素数
	private static final BigInteger p  = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",16);
	//因子系数 1
	private static final int h  = 1;
	/*-----------------------国密算法相关参数end-----------------------------*/
	//一些必要类
	public final ECFieldElement ecc_gx_fieldelement;
	public final ECFieldElement ecc_gy_fieldelement;
	public final ECCurve ecc_curve;
	public final ECPoint ecc_point_g;
	public final ECDomainParameters ecc_bc_spec;
	public final ECKeyPairGenerator ecc_key_pair_generator;
	/**
	 * 初始化方法
	 * @return
	 */
	public static SM2Factory getInstance(){
		return new SM2Factory();
	}
	public SM2Factory() {

		this.ecc_gx_fieldelement = new Fp(this.p,this.gx);
		this.ecc_gy_fieldelement = new Fp(this.p, this.gy);

		this.ecc_curve = new ECCurve.Fp(this.p, this.a, this.b);

		this.ecc_point_g = new ECPoint.Fp(this.ecc_curve, this.ecc_gx_fieldelement,this.ecc_gy_fieldelement);
		this.ecc_bc_spec = new ECDomainParameters(this.ecc_curve, this.ecc_point_g, this.n);

		ECKeyGenerationParameters ecc_ecgenparam;
		ecc_ecgenparam = new ECKeyGenerationParameters(this.ecc_bc_spec, new SecureRandom());

		this.ecc_key_pair_generator = new ECKeyPairGenerator();
		this.ecc_key_pair_generator.init(ecc_ecgenparam);
	}
	/**
	 * 根据私钥、曲线参数计算Z
	 * @param userId
	 * @param userKey
	 * @return
	 */
	public  byte[] sm2GetZ(byte[] userId, ECPoint userKey){
		SM3Digest sm3 = new SM3Digest();

		int len = userId.length * 8;
		sm3.update((byte) (len >> 8 & 0xFF));
		sm3.update((byte) (len & 0xFF));
		sm3.update(userId, 0, userId.length);

		byte[] p = Util.byteConvert32Bytes(this.a);
		sm3.update(p, 0, p.length);

		p = Util.byteConvert32Bytes(this.b);
		sm3.update(p, 0, p.length);

		p = Util.byteConvert32Bytes(this.gx);
		sm3.update(p, 0, p.length);

		p = Util.byteConvert32Bytes(this.gy);
		sm3.update(p, 0, p.length);

		p = Util.byteConvert32Bytes(userKey.normalize().getXCoord().toBigInteger());
		sm3.update(p, 0, p.length);

		p = Util.byteConvert32Bytes(userKey.normalize().getYCoord().toBigInteger());
		sm3.update(p, 0, p.length);

		byte[] md = new byte[sm3.getDigestSize()];
		sm3.doFinal(md, 0);
		return md;
	}
	
	public BigInteger sm2Random(SM2Result sm2Result) {
		BigInteger k = null;
		ECPoint kp = null;
		AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
		
		
		k = ecpriv.getD();
		kp = ecpub.getQ();
		
		sm2Result.keyra=kp;
		return k;
		
	}
	
	public void sm2singleSign(byte[] md, BigInteger userD, ECPoint userKey, BigInteger k, SM2Result sm2Result) {
		BigInteger e_i = new BigInteger(1, md);
		BigInteger r_i = null;
		BigInteger s_i = null;
		
		long startTime = System.nanoTime();
		r_i = e_i.add(sm2Result.keyra.getXCoord().toBigInteger());
		r_i = r_i.mod(this.n);
		if(r_i.equals(BigInteger.ZERO) || r_i.add(k).equals(this.n)||r_i.toString(16).length()!=64) {
			System.out.println("Invalid Alert: Re-Generate Randomness.");
			
		}
		s_i = r_i.multiply(userD);
		s_i = k.subtract(s_i).mod(this.n);
		
		long endTime = System.nanoTime(); 
		System.out.println("Core Local Computation:" + (endTime - startTime) + "ns");
		
		sm2Result.s_i = s_i;
		sm2Result.r = r_i;
		
	}
	
	public void sm2ms(SM2Result sm2result, byte[] privK) {
		
		BigInteger s_i = null;
	    BigInteger s=null;
	    BigInteger r = null;
	    int partynum = sm2result.partyNumber;
	    
	    long startTime2 = System.nanoTime();
		s_i = sm2result.s_i.mod(this.n);
		s_i = s_i.modInverse(this.n);
		
		byte[] formatedPri = new byte[32];
		System.arraycopy(privK, 0, formatedPri, 0, 32);
		BigInteger userD = new  BigInteger(formatedPri);
		
		
		BigInteger da_1 = userD.add(BigInteger.ONE);
		da_1 = da_1.mod(this.n);
        s = da_1.multiply(s_i).mod(this.n);
        
        
		for (int i=1; i< partynum; i++) {
    		byte[] formatedPriv = new byte[32];
    		System.arraycopy(privK, i*32, formatedPriv, 0, 32);
    		BigInteger userSK = new  BigInteger(formatedPriv);
    		BigInteger da_2 = userSK.add(BigInteger.ONE);
    		da_2 = da_2.mod(this.n);
            r = da_2.multiply(s_i).mod(this.n);
            s = s.add(r).mod(this.n);
    	}
	
		    s = s.mod(this.n);
		    sm2result.s = s;
		     long endTime2 = System.nanoTime(); 
			  System.out.println("Simulated Co-sining Time:"+ (endTime2 - startTime2) + "ns\n");
		    
		
	}
	
	
   
	
	public void sm2msVrfy(byte[] mdlist, byte[] publickey, SM2Result sm2Result) {
		
		byte[] randomlist = sm2Result.randomK;
		int partynum = sm2Result.partyNumber;
		BigInteger partyNum = BigInteger.valueOf(partynum);
		ECPoint[] userKey = new ECPoint[partynum];
	    ECPoint[] randomKey = new ECPoint[partynum];
	    ECPoint pubKey = null;
	    ECPoint mulPub = null;
	    ECPoint addPub = null;
	    ECPoint randK = null;
		BigInteger r1 = null;
		BigInteger r0 = null;
		BigInteger s = sm2Result.s;
		
		//test
		
		//ECPoint[] test = new ECPoint[partynum];
		
		long startTime3 = System.nanoTime();
	   
	        	for (int i=0,j=0; i< publickey.length; i=i+65,j++) {
	        		byte[] formatedPub = new byte[65];
	        		byte[] formatedRan = new byte[65];
	        		System.arraycopy(publickey, i, formatedPub, 0, 65);
	        		System.arraycopy(randomlist, i, formatedRan, 0, 65);
	        		
	        		ECPoint tempKey = this.ecc_curve.decodePoint(formatedPub);
	        		ECPoint tempRan = this.ecc_curve.decodePoint(formatedRan);
	        		userKey[j] = tempKey;
	        		randomKey[j] = tempRan;
	        		//System.out.println(Util.byteToHex(tempKey.getEncoded()));
	        		//System.out.println(Util.byteToHex(userKey[j].getEncoded()));
	        		//System.out.println(Util.byteToHex(randomKey[j].getEncoded()));
	        		//test[j] = randomKey[j].multiply(s);
	        		
	        	}
	        	//test
//	        	for(int i=1;i<partynum;i++) {
//	        		test[0]=test[0].add(test[i]);
//	        	}
//	        	System.out.println(Util.byteToHex(test[0].getEncoded()));
	        	
	        	 byte [] md = new byte[32];
				 System.arraycopy(mdlist, 0, md, 0, 32);
				 BigInteger e0 = new BigInteger(1, md);
				 r0 = e0.add(randomKey[0].getXCoord().toBigInteger());
				 r0 = r0.mod(this.n);
				 addPub = userKey[0];
				 mulPub = userKey[0].multiply(r0);
				 randK = randomKey[0];
				 //System.out.println(Util.getHexString(md));
				 //System.out.println(r0);
				 
			 for (int i=1; i < partynum; i++ ) {
				 byte [] md1 = new byte[32];
				 System.arraycopy(mdlist, i*32, md1, 0, 32);
			
				 BigInteger e1 = new BigInteger(1, md1);
				 
				 r1 = e1.add(randomKey[i].getXCoord().toBigInteger());
				 r1 = r1.mod(this.n);			
				 //System.out.println(r1);
				 addPub = addPub.add(userKey[i]);
				 mulPub = userKey[i].multiply(r1).add(mulPub);
				 randK = randK.add(randomKey[i]);
			 }

	
				//ECPoint x1y1 = ecc_point_g.multiply(sm2Result.s);
			  
				ECPoint x1y1 = randK.multiply(s);
			
				//test
//				System.out.println(Util.byteToHex(x1y1.getEncoded()));
//				k = k.multiply(s);
//				test[0] = this.ecc_point_g.multiply(k);
//				System.out.println(Util.byteToHex(test[0].getEncoded()));

				ECPoint x2y2 = mulPub.multiply(s);
				x1y1 = x1y1.subtract(x2y2);
				sm2Result.verify1 =x1y1;
				
				//test
//				System.out.println(Util.byteToHex(x1y1.getEncoded()));
//				
//				BigInteger kst = sm2Result.s_i;
//				k = kst.mod(this.n);
//				
//				BigInteger ks1 = k.multiply(s);
//				BigInteger ks2 = kst.multiply(s);
//				test[0] = this.ecc_point_g.multiply(ks1);
//				System.out.println(Util.byteToHex(test[0].getEncoded()));
//				test[1] = this.ecc_point_g.multiply(ks2);
//				System.out.println(Util.byteToHex(test[1].getEncoded()));
				
				
				ECPoint x3y3 = this.ecc_point_g.multiply(partyNum);
				x3y3 = x3y3.add(addPub);
				sm2Result.verify2 = x3y3;
			
				
				  long endTime3 = System.nanoTime(); 
				  System.out.println("Verfication Time:"+ (endTime3 - startTime3) + "ns\n");
				//sm2Result.R = e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(this.n);
				//System.out.println("R: " + sm2Result.R.toString(16));
				return;
			
			}
	
	/**
	 * 签名相关值计算
	 * @param md
	 * @param userD
	 * @param userKey
	 * @param sm2Result
	 */
	public void sm2Sign(byte[] md, BigInteger userD, ECPoint userKey, SM2Result sm2Result) {
		BigInteger e = new BigInteger(1, md);
		BigInteger k = null;
		ECPoint kp = null;
		BigInteger r = null;
		BigInteger s = null;
		
		//long startTime = System.nanoTime();
		do {
			do {
				// 正式环境
				
				AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.generateKeyPair();
				ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
				ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
				
				
				k = ecpriv.getD();
				kp = ecpub.getQ();
				
				r = e.add(kp.getXCoord().toBigInteger());
				r = r.mod(this.n);
				
				
			} while (r.equals(BigInteger.ZERO) || r.add(k).equals(this.n)||r.toString(16).length()!=64);

			// (1 + dA)~-1
			BigInteger da_1 = userD.add(BigInteger.ONE);
			da_1 = da_1.mod(this.n);
			//da_1 = da_1.modInverse(this.n);
			// s
			s = r.multiply(userD);
			s = k.subtract(s).mod(this.n);
			
			s = s.modInverse(this.n);
			
			s = da_1.multiply(s).mod(this.n);
			
		} while (s.equals(BigInteger.ZERO)||(s.toString(16).length()!=64));
		//long endTime = System.nanoTime(); 
		//System.out.println("The Running Time:" + (endTime - startTime) + "ns");
		
		sm2Result.r = r;
		sm2Result.s = s;
		sm2Result.keyra=kp;
	
	}
	/**
	 * 验签
	 * @param md sm3摘要
	 * @param userKey 根据公钥decode一个ecpoint对象
	 * @param r 没有特殊含义
	 * @param s 没有特殊含义
	 * @param sm2Result 接收参数的对象
	 */
	public void sm2Verify(byte md[], ECPoint userKey, BigInteger r,
                          BigInteger s, SM2Result sm2Result) {
		sm2Result.R = null;
		BigInteger e = new BigInteger(1, md);
		BigInteger t = r.add(s).mod(this.n);
		
		BigInteger r1 = null;
		ECPoint kk = sm2Result.keyra;
		r1 = e.add(kk.getXCoord().toBigInteger());
		r1 = r1.mod(this.n);
		if (t.equals(BigInteger.ZERO)) {
			return;
		} else {
			//ECPoint x1y1 = ecc_point_g.multiply(sm2Result.s);
			
			ECPoint x1y1 = sm2Result.keyra.multiply(sm2Result.s);
			//System.out.println("计算曲线点X0: "+ x1y1.normalize().getXCoord().toBigInteger().toString(16));
			//System.out.println("计算曲线点Y0: "+ x1y1.normalize().getYCoord().toBigInteger().toString(16));
			//System.out.println("");
			
			ECPoint x2y2 = userKey.multiply(r1);
			x2y2 = x2y2.multiply(sm2Result.s);
			x1y1 = x1y1.subtract(x2y2);
			
			//x1y1 = x1y1.subtract(x2y2);
			
	//		x1y1 = x1y1.add(userKey.multiply(t));
			//System.out.println("计算曲线点X1: "+ x1y1.normalize().getXCoord().toBigInteger().toString(16));
			//System.out.println("计算曲线点Y1: "+ x1y1.normalize().getYCoord().toBigInteger().toString(16));
			//System.out.println("");
			
			sm2Result.keyrb =x1y1;
	//		sm2Result.R = e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(this.n);
			//System.out.println("R: " + sm2Result.R.toString(16));
			return;
		}
	}

}
