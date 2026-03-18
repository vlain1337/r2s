# React2Shell Scanner - Security Write-Up

# Overview
React2Shell Scanner is a static analysis tool that detects Remote Code Execution (RCE) vulnerabilities in React applications.

# Methodology
The tool scans for dangerous patterns, including:
- Dynamic imports with unvalidated user input
- Unsafe use of dangerouslySetInnerHTML
- Insecure deserialization with eval()
- Server-side rendering (SSR) misconfigurations

# Key Findings

| Severity | Finding | Description |
|----------|---------|-------------|
| Critical | Dynamic Import Injection | User input passed directly to import() or require() |
| High | Unsanitized HTML | User data rendered via dangerouslySetInnerHTML |
| High | Insecure Eval | Use of eval() with user-controlled strings |
| Medium | SSR State Exposure | Sensitive data exposed in window.__INITIAL_STATE__ |

# Remediation
- Validate all input used in dynamic imports against an allowlist
- Sanitize HTML with a library like DOMPurify before rendering
- Eliminate eval() and similar functions from the codebase
- Redact sensitive data from server-side rendered state objects

# Usage
```bash
run start.bat
