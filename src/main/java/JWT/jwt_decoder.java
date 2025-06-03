package JWT;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class jwt_decoder {
    // 解码JWT，返回header和payload的JSON字符串数组
    public static String[] decode(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid JWT format");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), "UTF-8");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), "UTF-8");
        return new String[]{headerJson, payloadJson};
    }

    // 校验签名
    public static boolean verify(String jwt, String key) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return false;
        
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String providedSignature = parts[2];
        
        // 获取算法类型
        String headerJson = new String(Base64.getUrlDecoder().decode(headerB64), "UTF-8");
        JsonObject headerObj = JsonParser.parseString(headerJson).getAsJsonObject();
        String alg = headerObj.get("alg").getAsString();
        
        // 根据算法类型验证签名
        if ("RS256".equals(alg)) {
            return verifyRS256(headerB64 + "." + payloadB64, providedSignature, key);
        } else {
            return verifyHS256(headerB64 + "." + payloadB64, providedSignature, key);
        }
    }
    
    // HMAC SHA256 验证
    private static boolean verifyHS256(String data, String providedSignature, String secret) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        hmac.init(keySpec);
        byte[] sig = hmac.doFinal(data.getBytes("UTF-8"));
        String calculatedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        
        return providedSignature.equals(calculatedSignature);
    }
    
    // RSA SHA256 验证
    private static boolean verifyRS256(String data, String providedSignature, String publicKeyStr) throws Exception {
        // 处理公钥格式 (移除PEM头尾和换行符)
        publicKeyStr = publicKeyStr.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                                 .replaceAll("-----END PUBLIC KEY-----", "")
                                 .replaceAll("\\s", "");
        
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes("UTF-8"));
        
        byte[] signatureBytes = Base64.getUrlDecoder().decode(providedSignature);
        return signature.verify(signatureBytes);
    }
}
