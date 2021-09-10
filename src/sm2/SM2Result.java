package sm2;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * SM2
 */
public class SM2Result {
	public String sm3_digest;
	public String sm2_ms;
	public SM2Result() {
	}
	public int partyNumber;
	// 签名r

	public BigInteger r;
	public BigInteger s;
	public BigInteger s_i; //single part signature
	//验签R
	public BigInteger R;
	
	// 密钥交换
	public byte[] randomK; //The random ECPoints K in list
	public byte[] userID;
//	public byte[] s1;
//	public byte[] s2;

	public ECPoint keyra;
	public ECPoint keyrb;// hash value of publickeylist+randomkeylist, same for everyone
	public ECPoint verify1;
	public ECPoint verify2;
	
	//check
	public String getSm3_digest() {
		return sm3_digest;
	}
	public void setSm3_digest(String sm3_digest) {
		this.sm3_digest = sm3_digest;
	}
	public void setSm2_ms(String sm2_ms) {
		this.sm2_ms = sm2_ms;
	}
	public String getSm2_ms() {
		return sm2_ms;
	}
}
