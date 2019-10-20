import io.restassured.builder.RequestSpecBuilder;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by IntelliJ IDEA.
 * User: David Smiles
 * Date: 14/10/2019
 * Time: 15:31 PM
 *
 *  Test harness for testing the generation and validation of JWT tokens (CO-7520 gen and CO-7518 val)
 */

public class tokenTests {

    private static RequestSpecification requestSpec;

    private static final String CONTEGO_ORGANISATION_UID = "b43e8794-906c-4ea1-bbf7-98a14da8ea44";

    private static final String CONTEGO_ACCESS_KEY = "<INSERT ACCESS KEY>";

    private static final String BASE_URI = "https://api-qa.northrow.com";

    private static final String SVC_URL = "/authorise";

    private static final String EXPIRED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXZpZHNtaWxlcyIsIm9yZyI6ImI0M2U4Nzk0LTkwNmMtNGVhMS1iYmY3LTk4YTE0ZGE4ZWE0NCIsInJvbGVzIjpbIkFETUlOIl0sImV4cCI6MTU3MTA3MjE0MywiaWF0IjoxNTcxMDcwMzQzfQ.REgcF6EiVLlsHjzAWHH9uJolWCx6I4cMqHSfGO-xkjw";

    public static final String ORGANISATION_UID_MUST_NOT_BE_BLANK = "'organisation_uid': must not be blank.";

    public static final String ACCESS_KEY_MUST_NOT_BE_BLANK = "'access_key': must not be blank.";

    private static final String INVALID_ORGANISATION_UID_OR_ACCESS_KEY = "Invalid organisation_uid or access_key";


    @BeforeClass
    public static void setup()
    {
        // Create standard request for use across tests
        // log request and response for better debugging.
        // You can also only log if a requests fails.

        requestSpec = new RequestSpecBuilder()
                .setContentType(ContentType.JSON)
                .setBaseUri(BASE_URI)
                .addFilter(new ResponseLoggingFilter())
                .addFilter(new RequestLoggingFilter())
                .build();
    }

    @Test
    public void givenValidCredentials_whenPosted_thenCreateToken()
    {
        // Given
        Map<String, String> params = createJwtBody(CONTEGO_ORGANISATION_UID, CONTEGO_ACCESS_KEY);

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
        assertThat(payloadJson.getString("org")).isEqualTo(CONTEGO_ORGANISATION_UID);
        assertThat(payloadJson.getString("roles")).isEqualTo("[ADMIN]");
        // Dates exp and iat change need to mask these - do something with JSON

        // Assert on the expected signature values
        // Cannot test signature right now
    }

    @Test
    public void givenBlankOrgUid_whenPosted_thenFail()
    {
        // Given
        Map<String, String> params = createJwtBody("", CONTEGO_ACCESS_KEY);

        // When
        String message = given()
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
        assertThat(message).isEqualTo(ORGANISATION_UID_MUST_NOT_BE_BLANK);
    }

    @Test
    public void givenBlankAccessKey_whenPosted_thenFail()
    {
        // Given
        Map<String, String> params = createJwtBody(CONTEGO_ORGANISATION_UID, "");

        // When
        String message = given()
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
        assertThat(message).isEqualTo(ACCESS_KEY_MUST_NOT_BE_BLANK);
    }

    @Test
    public void givenInvalidOrgUid_whenPosted_thenFail()
    {
        // Given
        Map<String, String> params = createJwtBody("666", CONTEGO_ACCESS_KEY);

        // When
        String message = given()
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
        assertThat(message).isEqualTo(INVALID_ORGANISATION_UID_OR_ACCESS_KEY);
    }

    @Test
    public void givenInvalidAccessKey_whenPosted_thenFail()
    {
        // Given
        Map<String, String> params = createJwtBody(CONTEGO_ORGANISATION_UID, "666");

        // When
        String message = given()
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
        assertThat(message).isEqualTo(INVALID_ORGANISATION_UID_OR_ACCESS_KEY);
    }

    @Test
    public void givenValidToken_whenGetResource_thenAllow()
    {
        // Given
        Map<String, String> params = createJwtBody(CONTEGO_ORGANISATION_UID, CONTEGO_ACCESS_KEY);

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

        // Attempt to access non-existent url. If token valid, then will get 404 (not found),
        // otherwise it will get 403 (access denied)

        JsonPath jPath = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + jwtToken )
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_NOT_FOUND)
                .extract()
                .jsonPath();

        // Then
        assertThat(jPath.getString("status")).isEqualTo("404");
        assertThat(jPath.getString("error")).isEqualTo("Not Found");
        assertThat(jPath.getString("message")).isEqualTo("No message available");
        assertThat(jPath.getString("path")).isEqualTo("/helloQA");
    }

    @Test
    public void givenExpiredToken_whenGetResource_thenDeny()
    {
        // Given

        // When - Request a resource supplying an expired JWT token - expect access denied
        JsonPath jPath = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + EXPIRED_TOKEN )
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_FORBIDDEN)
                .extract()
                .jsonPath();

        // Then
        assertThat(jPath.getString("status")).isEqualTo("403");
        assertThat(jPath.getString("error")).isEqualTo("Forbidden");
        assertThat(jPath.getString("message")).isEqualTo("Access Denied");
        assertThat(jPath.getString("path")).isEqualTo("/helloQA");
    }

    @Test
    public void givenNoToken_whenGetResource_thenDeny()
    {
        // Given

        // When - Given Authorization header with no token
        JsonPath jPath = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer ")
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_FORBIDDEN)
                .extract()
                .jsonPath();

        // Then
        assertThat(jPath.getString("status")).isEqualTo("403");
        assertThat(jPath.getString("error")).isEqualTo("Forbidden");
        assertThat(jPath.getString("message")).isEqualTo("Access Denied");
        assertThat(jPath.getString("path")).isEqualTo("/helloQA");
    }

    @Test
    public void givenNoAuthorizationHeader_whenGetResource_thenDeny()
    {
        // Given

        // When - No Authorization header given
        JsonPath jPath = given()
                .spec(requestSpec)
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_FORBIDDEN)
                .extract()
                .jsonPath();

        // Then
        assertThat(jPath.getString("status")).isEqualTo("403");
        assertThat(jPath.getString("error")).isEqualTo("Forbidden");
        assertThat(jPath.getString("message")).isEqualTo("Access Denied");
        assertThat(jPath.getString("path")).isEqualTo("/helloQA");
    }

    @Test
    public void givenHackedToken_whenGetResource_thenDeny()
    {
        // Given
        Map<String, String> params = createJwtBody(CONTEGO_ORGANISATION_UID, CONTEGO_ACCESS_KEY);

        // When - Given a hacked decoded/hacked/re-encoded token
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

        // Attempt to access secured resourced, expect HTTP 403 (access denied)
        JsonPath jPath = given()
                .spec(requestSpec)
                .header("Authorization", "Bearer " + newToken )
                .when()
                .get("/helloQA")
                .then()
                .assertThat()
                .statusCode(HttpStatus.SC_FORBIDDEN)
                .extract()
                .jsonPath();

        // Then
        assertThat(jPath.getString("status")).isEqualTo("403");
        assertThat(jPath.getString("error")).isEqualTo("Forbidden");
        assertThat(jPath.getString("message")).isEqualTo("Access Denied");
        assertThat(jPath.getString("path")).isEqualTo("/helloQA");
    }


    /**
     * Creates a new map of key-value pairs representing the JWT token
     *
     * @param organisation_uid  the UID for the organisation
     * @param access_key  the acccess key associated with a user account
     * @return a map of key-value pairs
     */
    private Map<String, String> createJwtBody(String organisation_uid, String access_key) {
        Map<String, String> params = new HashMap<>();
        params.put("organisation_uid", organisation_uid);
        params.put("access_key", access_key);
        return params;
    }


    /**
     * Request a new JWT token from the server
     *
     * @param params - the map of key value pairs representing the
     *                 user token request
     * @return the HTTP response
     */
    private Response requestJwtToken(Map<String, String> params)
    {
        return given()
                .spec(requestSpec)
                .body(params)
                .when()
                .post("/authorise")
                .thenReturn();
    }

    /**
     * Request a secured dummy resource on the server. Must supply the
     * JWT token in the Authorization header.
     *
     * @param jwtToken the JWT Authorization token
     * @return the HTTP response
     */

    private Response getResource(String jwtToken)
    {
        return given()
                .header("Authorization", "Bearer " + jwtToken )
                .spec(requestSpec)
                .when()
                .get("/helloQA")
                .thenReturn();
    }
}
