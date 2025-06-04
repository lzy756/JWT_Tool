package JWT;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) throws Exception {
        // Read secret key from "public.key" like the Node.js example
        String key = new String(Files.readAllBytes(Paths.get("public.key")), StandardCharsets.UTF_8);

        // Construct header and payload used in the Node.js snippet
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"user\":\"admin\"}";

        // Sign using HS256 with the provided key
        String jwt = jwt_encoder.encode(headerJson, payloadJson, key);
        System.out.println(jwt);
    }
}