package JWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class jwt_encoder {
    // 生成JWT
    public static String encode(String headerJson, String payloadJson, String secret) throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes("UTF-8"));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes("UTF-8"));
        String signature = sign(header + "." + payload, secret);
        return header + "." + payload + "." + signature;
    }

    // 使用HMAC SHA256签名
    private static String sign(String data, String secret) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        hmac.init(keySpec);
        byte[] sig = hmac.doFinal(data.getBytes("UTF-8"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
}
