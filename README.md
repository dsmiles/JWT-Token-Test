# Introduction

This repo contains a simple test class for running some integration tests against a JWT based authentication endpoint 
that I was working.

The test class attempts to access a secured resource on a server that requires authentication (in this case a JWT 
Authentication token).

The authentication scenario is as follows:
1. Call the authentication endpoint with an organisation ID and access key
2. Retrieve the generated JWT token
3. Access the secured resource using the JWT Token
4. Check the expected response

The test class runs: 
- tests with valid parameters
- tests with missing parameters
- tests with invalid parameters
- verify the expected HTTP status codes
- verify the expected error messages
- verify the expected JWT header, payload, signature
- attempt to rewrite user account in JWT payload

Note: 
The scope is limited to the testing of the secured resources NOT the actual JWT authentication mechanism.  

### Requirements

This example was written using the following:
- Java 8 (now updated to Java 17)
- Maven
- Git
- REST-assured [here](https://rest-assured.io)
- AssertJ [here](https://assertj.github.io/doc/)

This test harness is built and tested for local use and is not intended to be run in production. However, I have run it
against the authentication endpoint in the QA environment.

### Usage
To run the test class against the authentication endpoint, open a terminal window and enter the commands:

```
git clone https://github.com/dsmiles/JWT-Token-Test.git
cd JWT-Token-Test
mvn test
```

### Configuration:
In order to run the tests you must define the following environment variables either from the command line or your IDEs
run configuration:

| Environment Variable | Description                                   |
|----------------------|-----------------------------------------------|
| ORGANISATION_UID     | Your organisation uid from the application    |
| ACCESS_KEY           | Your access key from the application UI       |
| SECRET_KEY           | Your secret key from the application database |

To obtain the values you must log into your account and access your profile settings on the application UI. The secret
key must be retrieved from the database.

I could have defined these variables in a property file, but chose to use environment variables since there were only
three of them.

