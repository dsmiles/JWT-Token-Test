import io.restassured.builder.RequestSpecBuilder;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by IntelliJ IDEA.
 * User: David Smiles
 * Date: 14/10/2019
 * Time: 15:31 PM
 * Simple test class for testing the generation and validation of JWT tokens (tickets CO-7520 and CO-7518)
 */

public class JwtTokenTests {

    private static RequestSpecification requestSpec;
    private static String organisationUid;
    private static String accessKey;
    private static String secretKey;
    private static final long TOKEN_VALIDITY_DURATION_IN_SECONDS = 1800L;
    private static final String BASE_URI = "https://localhost:8080";
    private static final String EXPIRED_ACCESS_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXZpZHNtaWxlcyIsIm9yZyI6ImI0M2U4Nzk0LTkwNmMtNGVhMS1iYmY3LTk4YTE0ZGE4ZWE0NCIsInJvbGVzIjpbIkFETUlOIl0sImV4cCI6MTU3MTA3MjE0MywiaWF0IjoxNTcxMDcwMzQzfQ.REgcF6EiVLlsHjzAWHH9uJolWCx6I4cMqHSfGO-xkjw";
    private static final String ORGANISATION_UID_MUST_NOT_BE_BLANK = "'organisation_uid': must not be blank.";
    private static final String ACCESS_KEY_MUST_NOT_BE_BLANK = "'access_key': must not be blank.";
    private static final String INVALID_ORGANISATION_UID_OR_ACCESS_KEY = "Invalid organisation_uid or access_key";
    private static final String RESOURCE_NOT_FOUND = "Resource not found";
    private static final String ACCESS_TOKEN_IS_MISSING = "Access token is missing";
    private static final String ACCESS_TOKEN_IS_INVALID = "Access token is invalid";
    private static final String ACCESS_TOKEN_EXPIRED = "Access token expired";

    @BeforeClass
    public static void setup()
    {
        organisationUid = System.getenv("ORGANISATION_UID");
        if (organisationUid == null) {
            throw new IllegalArgumentException("Organisation UID has not been defined");
        }

        accessKey = System.getenv("ACCESS_KEY");
        if (accessKey == null) {
            throw new IllegalArgumentException("Access key has not been defined");
        }

        secretKey = System.getenv("SECRET_KEY");
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key has not been defined");
        }

        requestSpec = new RequestSpecBuilder()
                .setContentType(ContentType.JSON)
                .setBaseUri(BASE_URI)
                .addFilter(new ResponseLoggingFilter())
                .addFilter(new RequestLoggingFilter())
                .build();
    }

    @Test
    public void givenValidCredentials_whenPosted_thenSuccess() throws NoSuchAlgorithmException, InvalidKeyException {
        // Given
        Map<String, String> params = createJwtBody(organisationUid, accessKey);

        // When
        String jwtToken = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .jsonPath()
                .getString("token");

        // Split the JWT token into the three parts (header, payload, signature)
        String[] encodedTokens = jwtToken.split("\\.");

        // Decode the three parts
        String header = new String(Base64.decodeBase64(encodedTokens[0].getBytes()));
        String payload = new String(Base64.decodeBase64(encodedTokens[1].getBytes()));
        String signature = new String(Base64.decodeBase64(encodedTokens[2].getBytes()));

        // Extract JSON from the parts
        JsonPath headerJson = JsonPath.from(header);
        JsonPath payloadJson = JsonPath.from(payload);
        JsonPath signatureJson = JsonPath.from(signature);

        // Assert on the expected header values
        assertThat(headerJson.getString("typ")).isEqualTo("JWT");
        assertThat(headerJson.getString("alg")).isEqualTo("HS256");

        // Assert on the expected payload values
        assertThat(payloadJson.getString("sub")).isEqualTo("davidsmiles");
        assertThat(payloadJson.getString("org")).isEqualTo(organisationUid);
        assertThat(payloadJson.getString("roles")).isEqualTo("[ADMIN]");

        // Assert on the expiry timestamp value
        // "exp" - Expires - The Unix timestamp of when the token expires
        // "iat" - Issued At - The Unix timestamp of when the token was issued
        long expires = Long.parseLong(payloadJson.getString("exp"));
        long issuedAt = Long.parseLong(payloadJson.getString("iat"));
        assertThat(expires).isEqualTo(issuedAt + TOKEN_VALIDITY_DURATION_IN_SECONDS);

        // Assert on the Signature Verification
        String encodedSignature = JWTUtils.calculateHMACSHA256(header + "." + payload, secretKey);
        String expectedSignature = new String(Base64.decodeBase64(encodedSignature));
        assertThat(signature).isEqualTo(expectedSignature);
    }

    @Test
    public void givenBlankOrgUid_whenPosted_thenBadRequest()
    {
        // Given
        Map<String, String> params = createJwtBody("", accessKey);

        // When
        String error = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ORGANISATION_UID_MUST_NOT_BE_BLANK);
    }

    @Test
    public void givenBlankAccessKey_whenPosted_thenBadRequest()
    {
        // Given
        Map<String, String> params = createJwtBody(organisationUid, "");

        // When
        String error = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ACCESS_KEY_MUST_NOT_BE_BLANK);
    }

    @Test
    public void givenInvalidOrgUid_whenPosted_thenUnauthorized()
    {
        // Given
        Map<String, String> params = createJwtBody("666", accessKey);

        // When
        String error = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(INVALID_ORGANISATION_UID_OR_ACCESS_KEY);
    }

    @Test
    public void givenInvalidAccessKey_whenPosted_thenUnauthorized()
    {
        // Given
        Map<String, String> params = createJwtBody(organisationUid, "666");

        // When
        String error = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(INVALID_ORGANISATION_UID_OR_ACCESS_KEY);
    }

    @Test
    public void givenValidToken_whenGetInvalidResource_thenNotFound()
    {
        // Given
        Map<String, String> params = createJwtBody(organisationUid, accessKey);

        // Request a valid access token
        String jwtToken = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .jsonPath()
                .getString("token");

        // When - Use valid token to attempt access to non-existent resource
        String error = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + jwtToken )
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_NOT_FOUND)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(RESOURCE_NOT_FOUND);
    }

    @Test
    public void givenNoToken_whenGetResource_thenUnauthorized()
    {
        // Given

        // When - Given Authorization header with no token
        String error = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer ")
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ACCESS_TOKEN_IS_MISSING);
    }

    @Test
    public void givenNoAuthorizationHeader_whenGetResource_thenUnauthorized()
    {
        // Given

        // When - No Authorization header
        String error = given()
                .spec(requestSpec)
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ACCESS_TOKEN_IS_MISSING);
    }

    @Test
    public void givenHackedToken_whenGetResource_thenUnauthorized()
    {
        // Given
        Map<String, String> params = createJwtBody(organisationUid, accessKey);

        // Request a valid access token
        String jwtToken = given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .jsonPath()
                .getString("token");

        // Split the JWT token into the three parts (header, payload, signature)
        String[] encodedTokens = jwtToken.split("\\.");

        // Decode the payload
        String payload = new String(Base64.decodeBase64(encodedTokens[1].getBytes()));

        // Replace the username with new value
        payload = payload.replaceAll("davidsmiles", "davidtest");

        // Re-encode the payload
        String encodedPayload = new String(Base64.encodeBase64URLSafe(payload.getBytes()));

        // Rebuild the JWT token with new username
        String newToken = encodedTokens[0] + "." + encodedPayload + "." + encodedTokens[2];

        // When - Use hacked token to attempt access to non-existent resource
        String error = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + newToken )
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ACCESS_TOKEN_IS_INVALID);
    }

    @Test
    public void givenExpiredToken_whenGetResource_thenUnauthorized()
    {
        // Given

        // When - Request a resource supplying an expired JWT token - expect access denied
        String error = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + EXPIRED_ACCESS_TOKEN)
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_UNAUTHORIZED)
                .extract()
                .jsonPath()
                .getString("message");

        // Then
        assertThat(error).isEqualTo(ACCESS_TOKEN_EXPIRED);
    }

    /**
     * Creates a new map of key-value pairs representing the JWT token
     *
     * @param organisation_uid the UID for the organisation
     * @param access_key the access key associated with a user account
     * @return a map of key-value pairs
     */
    private Map<String, String> createJwtBody(String organisation_uid, String access_key) {
        Map<String, String> params = new HashMap<>();
        params.put("organisation_uid", organisation_uid);
        params.put("access_key", access_key);
        return params;
    }

    /**
     * Request a new JWT access token from the server
     * @param params the map of key value pairs representing the user token
     * @return the JWT access token
     */
    private String requestJwtToken(Map<String, String> params)
    {
        return given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_OK)
                .extract()
                .jsonPath()
                .getString("token");
    }
}
