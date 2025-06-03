package JWT;

import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
    public static boolean verify(String jwt, String secret) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return false;
        
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String providedSignature = parts[2];
        
        // 计算签名
        String data = headerB64 + "." + payloadB64;
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        hmac.init(keySpec);
        byte[] sig = hmac.doFinal(data.getBytes("UTF-8"));
        String calculatedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        
        return providedSignature.equals(calculatedSignature);
    }
}
