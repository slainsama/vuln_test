# Avaje-Jex Path Traversal Vulnerability

## Information

### Basic Information

- **Vendor**: Avaje
- **Product**: Avaje-Jex Web Framework
- **Affected Component**: avaje-jex-file-upload module
- **Vulnerability Type**: Path Traversal (CWE-22)
- **Discovery Date**: October 17, 2025
- **Reporter**: s1ain

### Affected Versions

- **Product Version Range**: All versions <= 3.3-RC5
- **First Affected Version**: 3.3-RC5 (introduced in commit a6a74c3, October 6, 2025)
- **Platform**: All platforms (Cross-platform Java application)

## Vulnerability Summary

A path traversal vulnerability in the Avaje-Jex file upload module allows remote authenticated attackers to write arbitrary files to any location on the server filesystem via specially crafted filename parameters in HTTP multipart requests.

## Technical Details

### Vulnerability Description

The vulnerability exists in the `MultipartFormParser.parse()` method at lines 94-95 of `MultipartFormParser.java`. The method directly uses user-supplied filename parameters from HTTP multipart requests without proper validation or sanitization, allowing attackers to escape the intended upload directory using path traversal sequences (e.g., `../`) or absolute paths.

### Affected Code Location

```
File: avaje-jex-file-upload/src/main/java/io/avaje/jex/file/upload/MultipartFormParser.java
Lines: 94-95
Method: parse()
```

### Vulnerable Code Snippet

```java
var fileName = meta.filename != null ? meta.filename : meta.name + ".tmp";
var file = config.cacheDirectory().resolve(fileName).toFile();
```

### Attack Vector

- **Access Required**: Authenticated user with file upload permissions
- **Attack Complexity**: Low - Standard HTTP multipart request
- **User Interaction**: None required
- **Network Access**: Required (remote exploitation possible)

## Proof of Concept

### Basic Attack Example

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKit

------WebKit
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"
Content-Type: text/plain

malicious_content_here
------WebKit--
```

### Impact Demonstration

The above request would attempt to overwrite `/etc/passwd` on Unix-like systems, demonstrating the ability to write files outside the intended upload directory.

## Impact Assessment

### CVSS 3.1 Metrics

- **Base Score**: 8.8 (HIGH)
- **Vector String**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

### Impact Categories

- **Confidentiality**: High - Arbitrary file read through overwrite attacks
- **Integrity**: High - Arbitrary file write/modification capabilities  
- **Availability**: High - System disruption through critical file corruption

### Potential Consequences

1. **Remote Code Execution**: Web shell deployment in accessible directories
2. **System Compromise**: Overwriting critical system configuration files
3. **Privilege Escalation**: Modifying system files for elevated access
4. **Data Breach**: Unauthorized access to sensitive information

## Affected Systems

### Deployment Scenarios

- Web applications using Avaje-Jex framework with file upload functionality
- REST APIs implementing multipart file upload endpoints
- Any Java application utilizing the avaje-jex-file-upload module

### Prerequisites for Exploitation

- Application must use the FileUploadPlugin
- Attacker must have access to file upload endpoints
- Basic authentication to the application required

## Remediation Information

### Immediate Mitigation

Disable the FileUploadPlugin temporarily:

```java
// Remove or comment out:
// .plugin(FileUploadPlugin.create())
```

### Complete Fix

Implement proper filename validation and path sanitization:

```java
private static String sanitizeFileName(String originalFileName) {
    if (originalFileName == null || originalFileName.trim().isEmpty()) {
        return "unnamed_" + System.currentTimeMillis();
    }
    
    return originalFileName
        .replaceAll("[/\\\\]", "_")     // Remove path separators
        .replaceAll("\\.\\.+", "_")     // Remove path traversal sequences
        .replaceAll("^\\.|\\.$", "_");  // Remove leading/trailing dots
}
```

## Additional Information

### References

- **Product Repository**: https://github.com/avaje/avaje-jex
- **Vulnerable Commit**: https://github.com/avaje/avaje-jex/commit/a6a74c3
- **CWE Reference**: https://cwe.mitre.org/data/definitions/22.html
- **OWASP Guide**: https://owasp.org/www-community/attacks/Path_Traversal

### Contact Information

For additional technical details or clarification, please contact:

- **Reporter**: Claude Security Research Team
- **Report Date**: October 17, 2025

### Coordination

This vulnerability report is being submitted for CVE assignment. Coordinated disclosure with the vendor (Avaje) will be initiated following CVE assignment.

