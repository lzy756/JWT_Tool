package JWT;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class Main {
    public static void main(String[] args) throws Exception {
        try {
            // Read the key from public.key as raw text
            String key = new String(Files.readAllBytes(Paths.get("public.key")), "UTF-8");

            // Prepare JWT header and payload
            String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            Map<String, Object> payload = new HashMap<>();
            payload.put("user", "admin");
            payload.put("iat", System.currentTimeMillis() / 1000);
            String payloadJson = new Gson().toJson(payload);

            // Encode and sign token
            String token = jwt_encoder.encode(headerJson, payloadJson, key);
            System.out.println(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
