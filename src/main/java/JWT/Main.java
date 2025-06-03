package JWT;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
        // 示例：生成和解码JWT
        try {
//            String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
//            String payloadJson = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
//            String secret = "your-256-bit-secret";
//
//            // 生成JWT
//            String jwt = jwt_encoder.encode(headerJson, payloadJson, secret);
//            System.out.println("Generated JWT: " + jwt);
//
//            // 解码JWT
//            String[] decoded = jwt_decoder.decode(jwt);
//            System.out.println("Decoded Header: " + decoded[0]);
//            System.out.println("Decoded Payload: " + decoded[1]);
//
//            // 验证签名
//            boolean isValid = jwt_decoder.verify(jwt, secret);
//            System.out.println("Is JWT valid? " + isValid);
            String jwt_sess= "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImlhdCI6MTc0ODk1MTk1Mn0.fbvAKX98IEfzpX3lqAm_o8NbOFs9T4tNj8SVpW4Fh9XDyPQHy8Jucrd7Jlkuetcr8FdAxr7RUzi9hQX0d9UgFSEJwycLN3ry3H5TuEc6kWhe_gO2OAL7M6o2NIeHbHWAtAnIJbKXka55dhhGPtgyO3fvTYVW47p-AxRJhocL5kg";
            String privateKey = readKey("private.key");
            String publicKey = readKey("public.key");
            String[] decoded = jwt_decoder.decode(jwt_sess);
            System.out.println("Decoded Header: " + decoded[0]);
            System.out.println("Decoded Payload: " + decoded[1]);

            System.out.println("Is JWT valid? " + jwt_decoder.verify(jwt_sess, publicKey));

            Map<String, Object> map=new Gson().fromJson(decoded[1], Map.class);
            map.put("user","admin");
            String payloadJson = new Gson().toJson(map);
            System.out.println(map);
            String calc_jwt=jwt_encoder.encode(decoded[0], payloadJson, privateKey);
            System.out.println(calc_jwt);
//            System.out.println("is calc jwt equal to jwt_sess? " + calc_jwt.equals(jwt_sess));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}