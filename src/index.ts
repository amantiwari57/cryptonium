// Main entry point for Cryptonium - A comprehensive cryptographic hashing library
export * from './core/password';
export * from './core/security';
export * from './algorithms/sha256';
export * from './algorithms/sha512';
export * from './algorithms/pbkdf2';
export * from './algorithms/hmac';
export * from './utils/salt';
export * from './utils/timing';
export * from './utils/validation';
export * from './types';

// Re-export main functions for convenience
export { 
  hashPassword, 
  verifyPassword, 
  hashPasswordWithOptions,
  verifyPasswordSecure 
} from './core/password';

export { 
  sha256, 
  sha256Hex,
  sha256Bytes 
} from './algorithms/sha256';

export { 
  sha512, 
  sha512Hex,
  sha512Bytes 
} from './algorithms/sha512';

export { 
  pbkdf2,
  pbkdf2Hex,
  pbkdf2Bytes 
} from './algorithms/pbkdf2';

export {
  generateSalt,
  generateSecureSalt,
  generateCryptoSalt
} from './utils/salt';

export {
  timeSafeCompare,
  constantTimeCompare
} from './utils/timing';

// Default configuration
export const DEFAULT_CONFIG = {
  saltLength: 32,
  iterations: 100000,
  keyLength: 64,
  algorithm: 'sha256' as const,
  encoding: 'hex' as const
}; 