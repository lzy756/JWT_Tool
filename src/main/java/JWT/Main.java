package JWT;

public class Main {
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
            String jwt_sess="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZG1pbiIsImlhdCI6MTc0ODkzOTg0OSwiZXhwIjoxNzQ4OTQ3MDQ5LCJuYmYiOjE3NDg5Mzk4NDksInN1YiI6InVzZXIiLCJqdGkiOiJhYWMwZWE1NDg0YzIwOGE0MjkxNzYyMTBjZDk1ZTQ1ZCJ9.OMVudh6tdyXVAeUqfyXO4sOxjMzjqxzKLVc1jIGXZ54";
            String secret="123456";
            String[] decoded = jwt_decoder.decode(jwt_sess);
            System.out.println("Decoded Header: " + decoded[0]);
            System.out.println("Decoded Payload: " + decoded[1]);

            System.out.println("Is JWT valid? " + jwt_decoder.verify(jwt_sess, secret));

            String calc_jwt=jwt_encoder.encode(decoded[0], decoded[1], secret);
            System.out.println("is calc jwt equal to jwt_sess? " + calc_jwt.equals(jwt_sess));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}