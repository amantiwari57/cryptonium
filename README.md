# Cryptonium 🔐

A comprehensive cryptographic hashing library with SHA-256, SHA-512, PBKDF2, and advanced security features for Node.js applications.

[![npm version](https://badge.fury.io/js/cryptonium.svg)](https://badge.fury.io/js/cryptonium)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Pure JavaScript Implementation**: No native dependencies
- **Multiple Hash Algorithms**: SHA-256, SHA-512, PBKDF2, HMAC
- **Enhanced Security**: Salt generation, timing attack protection, configurable iterations
- **TypeScript Support**: Full type definitions included
- **Flexible API**: Simple functions for quick use, advanced options for fine control
- **Security Utilities**: Password strength assessment, secure password generation
- **Cross-Platform**: Works in Node.js environments
- **Timing Attack Resistant**: Constant-time comparisons for secure verification

## Installation

```bash
npm install cryptonium
```

## Quick Start

```typescript
import { hashPassword, verifyPassword } from 'cryptonium';

// Hash a password
const password = 'mySecurePassword123';
const hashedPassword = hashPassword(password);
console.log('Hashed:', hashedPassword);

// Verify a password
const isValid = verifyPassword(password, hashedPassword);
console.log('Valid:', isValid); // true

const isInvalid = verifyPassword('wrongPassword', hashedPassword);
console.log('Invalid:', isInvalid); // false
```

## Core API

### Password Hashing

#### `hashPassword(password, options?)`

Hash a password with salt and optional configuration.

```typescript
import { hashPassword } from 'cryptonium';

// Basic usage
const hash = hashPassword('myPassword');

// With options
const hashWithOptions = hashPassword('myPassword', {
  algorithm: 'sha256',
  saltLength: 32,
  iterations: 100000,
  keyLength: 64
});
```

#### `verifyPassword(password, storedHash)`

Verify a password against a stored hash with timing attack protection.

```typescript
import { verifyPassword } from 'cryptonium';

const isValid = verifyPassword('myPassword', storedHash);
```

#### `verifyPasswordSecure(password, storedHash)`

Async verification with detailed results and enhanced timing protection.

```typescript
import { verifyPasswordSecure } from 'cryptonium';

const result = await verifyPasswordSecure('myPassword', storedHash);
console.log('Valid:', result.isValid);
console.log('Time taken:', result.timeTaken, 'ms');
```

### Hash Algorithms

#### SHA-256

```typescript
import { sha256, sha256Hex, sha256Bytes } from 'cryptonium';

const hash = sha256('hello world');
// Returns: hex string

const bytes = sha256Bytes('hello world');
// Returns: Uint8Array
```

#### SHA-512

```typescript
import { sha512, sha512Hex, sha512Bytes } from 'cryptonium';

const hash = sha512('hello world');
const bytes = sha512Bytes('hello world');
```

#### PBKDF2

```typescript
import { pbkdf2, pbkdf2Hex, pbkdf2Bytes } from 'cryptonium';

const derived = pbkdf2('password', 'salt', 100000, 32);
```

### Salt Generation

```typescript
import { 
  generateSalt, 
  generateSecureSalt, 
  generateCryptoSalt 
} from 'cryptonium';

// Basic salt (Math.random based)
const basicSalt = generateSalt(16);

// Secure salt (multiple entropy sources)
const secureSalt = generateSecureSalt(32, {
  strategy: 'crypto',
  charset: 'secure'
});

// Crypto salt (crypto.randomBytes when available)
const cryptoSalt = generateCryptoSalt(32);
```

### Security Features

#### Password Strength Assessment

```typescript
import { assessPasswordStrength } from 'cryptonium';

const assessment = assessPasswordStrength('myPassword123!');
console.log('Score:', assessment.score);
console.log('Level:', assessment.level); // weak, fair, good, strong, very-strong
console.log('Feedback:', assessment.feedback);
```

#### Secure Password Generation

```typescript
import { generateSecurePassword } from 'cryptonium';

const password = generateSecurePassword(16, true); // length, includeSpecial
console.log('Generated:', password);
```

#### Timing-Safe Comparison

```typescript
import { timeSafeCompare, constantTimeCompare } from 'cryptonium';

const isEqual = timeSafeCompare('hash1', 'hash2');
const isEqualConstant = constantTimeCompare('hash1', 'hash2');
```

## Advanced Configuration

### Security Levels

```typescript
import { getSecurityLevel, createSecurityProfile } from 'cryptonium';

// Predefined security levels
const highSecurity = getSecurityLevel('high');
const maxSecurity = getSecurityLevel('maximum');

// Use case specific profiles
const webProfile = createSecurityProfile('web');
const enterpriseProfile = createSecurityProfile('enterprise');
```

### Custom Options

```typescript
import { hashPasswordWithOptions } from 'cryptonium';

const result = hashPasswordWithOptions('password', {
  algorithm: 'sha512',
  saltLength: 64,
  iterations: 200000,
  keyLength: 128,
  pepper: 'additional-secret'
});

console.log('Hash:', result.hash);
console.log('Salt:', result.salt);
console.log('Metadata:', result.metadata);
```

## Migration & Compatibility

### From bcrypt

```typescript
// Instead of bcrypt
// const hash = await bcrypt.hash(password, 10);
// const isValid = await bcrypt.compare(password, hash);

// Use cryptonium
const hash = hashPassword(password, { iterations: 50000 });
const isValid = verifyPassword(password, hash);
```

### Upgrading Existing Hashes

```typescript
import { needsRehashing, upgradePasswordHash } from 'cryptonium';

if (needsRehashing(oldHash, { iterations: 100000 })) {
  const newHash = await upgradePasswordHash(password, oldHash, {
    iterations: 100000,
    algorithm: 'sha512'
  });
  
  if (newHash) {
    // Save new hash to database
  }
}
```

## Performance & Security

### Recommended Settings

- **Web Applications**: 50,000 iterations, 24-byte salt
- **Mobile Apps**: 25,000 iterations, 20-byte salt  
- **Enterprise**: 200,000 iterations, 64-byte salt
- **APIs**: 100,000 iterations, 32-byte salt

### Security Best Practices

1. **Use Strong Salts**: Minimum 16 bytes, preferably 32+
2. **Sufficient Iterations**: At least 10,000, preferably 100,000+
3. **Timing Attack Protection**: Always enabled by default
4. **Regular Rehashing**: Upgrade old hashes periodically
5. **Pepper Support**: Add application-level secrets when needed

## Error Handling

```typescript
import { ValidationError, SecurityError } from 'cryptonium';

try {
  const hash = hashPassword(''); // Empty password
} catch (error) {
  if (error instanceof ValidationError) {
    console.log('Validation error:', error.message);
  }
}
```

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import { 
  HashOptions, 
  PasswordHashResult, 
  VerificationResult,
  SecurityLevel 
} from 'cryptonium';

const options: HashOptions = {
  algorithm: 'sha256',
  saltLength: 32,
  iterations: 100000
};
```

## License

MIT © Aman Tiwari

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

If you discover a security vulnerability, please send an email to amantiwari7057@gmail.com. All security vulnerabilities will be promptly addressed.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details about changes in each version.

---

**Note**: This library is designed for environments where crypto libraries like bcrypt might not work (e.g., Cloudflare Workers, Bun and some serverless environment). For maximum security in traditional Node.js environments, consider using established libraries like bcrypt or argon2. 
