import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for handling JWT operations.
 */
public class JWTUtils {

    /**
     * Calculates the HMACSHA256 signature for the given data using the provided key.
     *
     * @param data The data to be signed (e.g., concatenated header and payload).
     * @param key  The secret key used for signing.
     * @return The HMACSHA256 signature as a Base64-encoded string.
     * @throws NoSuchAlgorithmException If the algorithm "HmacSHA256" is not available.
     * @throws InvalidKeyException      If the provided key is invalid for HMACSHA256.
     */
    public static String calculateHMACSHA256(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        hmacSHA256.init(secretKey);
        byte[] hmacBytes = hmacSHA256.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}
