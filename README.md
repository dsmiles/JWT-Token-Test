# JWT Authentication Token Tests

This repository contains a simple REST-assured project for running integration tests against a JSON Web Token (JWT) 
based authentication endpoint that I had worked on.

The purpose is to send various HTTP requests to a secured resource on a server that requires authentication using JWT
tokens and verify the HTTP status codes returned.

The authentication scenario is as follows:

1. Call the authentication endpoint with an organisation ID and access key
2. Retrieve the generated JWT token
3. Access the secured resource using the JWT Token
4. Check the expected response

The test class covers the following scenarios:

- Tests with valid parameters
- Tests with missing parameters
- Tests with invalid parameters
- Verification of expected HTTP status codes
- Verification of expected error messages
- Verification of expected JWT header, payload, signature
- Attempt to rewrite user account in JWT payload

### Requirements

This example was written using the following:

- Java 8 (now updated to Java 17)
- Maven
- Git
- REST-assured [here](https://rest-assured.io)
- AssertJ [here](https://assertj.github.io/doc/)

### Usage

To run the test class against the authentication endpoint, open a terminal window and enter the commands:

1. Clone the repository:
```
git clone https://github.com/dsmiles/JWT-Token-Test.git
cd JWT-Token-Test
```

2. Run the Maven test command:
```
mvn test
```

### Configuration:

To run the tests you must define the following environment variables either from the command line or your IDEs
run configuration:

| Environment Variable | Description                                   |
|----------------------|-----------------------------------------------|
| ORGANISATION_UID     | Your organisation uid from the application    |
| ACCESS_KEY           | Your access key from the application UI       |
| SECRET_KEY           | Your secret key from the application database |

To obtain the values you must log into your account and access your profile settings on the application UI. The secret
key must be retrieved from the database.

Environment variables were chosen over a property file since there are only three of them.
