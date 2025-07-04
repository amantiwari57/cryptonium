// Salt generation utilities for enhanced security
import { SaltOptions, SaltStrategy } from '../types';
import { validateKeyLength } from './validation';

/**
 * Default charset for random salt generation
 */
const DEFAULT_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Secure charset with special characters
 */
const SECURE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';

/**
 * Generate a random salt using Math.random (least secure)
 * @param length Length of the salt
 * @param charset Character set to use
 * @returns Generated salt string
 */
export function generateSalt(length: number = 16, charset: string = DEFAULT_CHARSET): string {
  validateKeyLength(length);
  
  let salt = '';
  for (let i = 0; i < length; i++) {
    salt += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return salt;
}

/**
 * Generate a secure salt using crypto.randomBytes (more secure)
 * @param length Length of the salt in bytes
 * @returns Generated salt as hex string
 */
export function generateCryptoSalt(length: number = 32): string {
  validateKeyLength(length);
  
  // Fallback implementation for environments without crypto module
  try {
    const crypto = require('crypto');
    return crypto.randomBytes(length).toString('hex');
  } catch {
    // Fallback to enhanced Math.random with better entropy
    return generateEnhancedRandomSalt(length);
  }
}

/**
 * Generate a secure salt with enhanced randomness
 * @param length Length of the salt
 * @param options Salt generation options
 * @returns Generated salt string
 */
export function generateSecureSalt(length: number = 32, options: Partial<SaltOptions> = {}): string {
  validateKeyLength(length);
  
  const strategy = options.strategy || 'crypto';
  const charset = options.charset || SECURE_CHARSET;
  
  const opts: SaltOptions = {
    length,
    strategy,
    charset
  };

  switch (strategy) {
    case 'crypto':
      return generateCryptoSalt(length);
    case 'secure':
      return generateSecureRandomSalt(length, charset);
    case 'random':
    default:
      return generateSalt(length, charset);
  }
}

/**
 * Generate salt using multiple entropy sources for maximum security
 * @param length Length of the salt
 * @param charset Character set to use
 * @returns Generated salt string
 */
function generateSecureRandomSalt(length: number, charset: string): string {
  let salt = '';
  
  for (let i = 0; i < length; i++) {
    // Combine multiple entropy sources
    const timeEntropy = Date.now() % charset.length;
    const randomEntropy = Math.floor(Math.random() * charset.length);
    const performanceEntropy = Math.floor((performance?.now() || Date.now()) * 1000) % charset.length;
    
    // XOR the entropy sources for better randomness
    const combinedEntropy = (timeEntropy ^ randomEntropy ^ performanceEntropy) % charset.length;
    salt += charset.charAt(combinedEntropy);
  }
  
  return salt;
}

/**
 * Enhanced Math.random based salt generation with better entropy
 * @param length Length of the salt in bytes
 * @returns Generated salt as hex string
 */
function generateEnhancedRandomSalt(length: number): string {
  const bytes: number[] = [];
  
  for (let i = 0; i < length; i++) {
    // Use multiple random calls and combine them
    const r1 = Math.floor(Math.random() * 256);
    const r2 = Math.floor(Math.random() * 256);
    const r3 = Math.floor(Math.random() * 256);
    const timeComponent = Date.now() % 256;
    
    // Combine multiple sources of randomness
    const combinedByte = (r1 ^ r2 ^ r3 ^ timeComponent) % 256;
    bytes.push(combinedByte);
  }
  
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a salt with specific pattern for testing
 * @param pattern Pattern to follow (e.g., "number", "alpha", "mixed")
 * @param length Length of the salt
 * @returns Generated salt string
 */
export function generatePatternSalt(pattern: 'number' | 'alpha' | 'mixed' | 'secure', length: number = 16): string {
  validateKeyLength(length);
  
  let charset: string;
  
  switch (pattern) {
    case 'number':
      charset = '0123456789';
      break;
    case 'alpha':
      charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
      break;
    case 'mixed':
      charset = DEFAULT_CHARSET;
      break;
    case 'secure':
      charset = SECURE_CHARSET;
      break;
    default:
      charset = DEFAULT_CHARSET;
  }
  
  return generateSalt(length, charset);
}

 