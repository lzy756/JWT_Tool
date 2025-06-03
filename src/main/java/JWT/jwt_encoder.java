package JWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;

public class jwt_encoder {
    // 生成JWT
    public static String encode(String headerJson, String payloadJson, String secret) throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes("UTF-8"));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes("UTF-8"));
        
        // 从headerJson中提取算法类型
        String alg = headerJson.contains("RS256") ? "RS256" : "HS256";
        
        String signature;
        if ("RS256".equals(alg)) {
            signature = signRS256(header + "." + payload, secret);
        } else {
            signature = signHS256(header + "." + payload, secret);
        }
        
        return header + "." + payload + "." + signature;
    }

    // 使用HMAC SHA256签名
    private static String signHS256(String data, String secret) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        hmac.init(keySpec);
        byte[] sig = hmac.doFinal(data.getBytes("UTF-8"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
    
    // 使用RSA SHA256签名
    private static String signRS256(String data, String privateKeyStr) throws Exception {
        // 处理私钥格式 (移除PEM头尾和换行符)
        privateKeyStr = privateKeyStr.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                                   .replaceAll("-----END RSA PRIVATE KEY-----", "")
                                   .replaceAll("\\s", "");
        
        // 解码 Base64 编码的私钥
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        
        // 将PKCS#1格式转换为Java可用格式
        PrivateKey privateKey = parsePKCS1PrivateKey(privateKeyBytes);
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes("UTF-8"));
        byte[] sig = signature.sign();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
    
    // 解析 PKCS#1 格式的私钥
    private static PrivateKey parsePKCS1PrivateKey(byte[] pkcs1Bytes) throws Exception {
        // 使用 ASN.1 解析私钥结构
        ASN1InputStream asn1InputStream = new ASN1InputStream(pkcs1Bytes);
        ASN1Sequence seq = (ASN1Sequence) asn1InputStream.readObject();
        asn1InputStream.close();
        
        // PKCS#1 RSA 私钥包含 9 个整数
        // 第一个是版本，第二个是模数 n，第三个是公开指数 e，第四个是私有指数 d
        if (seq.size() != 9) {
            throw new IllegalArgumentException("Invalid RSA private key encoding");
        }
        
        // 获取模数 n
        BigInteger modulus = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        // 获取私有指数 d
        BigInteger privateExponent = ((ASN1Integer) seq.getObjectAt(3)).getValue();
        
        // 使用 RSAPrivateKeySpec 创建私钥
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
