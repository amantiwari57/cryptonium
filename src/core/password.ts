// Main password hashing functionality with enhanced security
import { sha256 } from '../algorithms/sha256';
import { generateSecureSalt } from '../utils/salt';
import { timeSafeCompare } from '../utils/timing';
import { validatePassword, validateStoredHashFormat } from '../utils/validation';
import { HashOptions, PasswordHashResult, VerificationResult } from '../types';

/**
 * Hash password with salt (enhanced version of original function)
 * @param password Password to hash
 * @param options Hashing options
 * @returns Hashed password string in format: salt:hash:metadata
 */
export function hashPassword(password: string, options: Partial<HashOptions> = {}): string {
  validatePassword(password);
  
  const algorithm = options.algorithm || 'sha256';
  const saltLength = options.saltLength || 32;
  const iterations = options.iterations || 1;
  const keyLength = options.keyLength || 64;
  const encoding = options.encoding || 'hex';
  
  const opts: HashOptions = {
    algorithm,
    saltLength,
    iterations,
    keyLength,
    encoding
  };
  
  const salt = generateSecureSalt(saltLength);
  let hash: string;
  
  switch (algorithm) {
    case 'sha256':
    default:
      hash = sha256(password + salt);
      // Apply multiple iterations for enhanced security
      for (let i = 1; i < iterations; i++) {
        hash = sha256(hash);
      }
      break;
  }
  
  const metadata = {
    algorithm: opts.algorithm,
    iterations: opts.iterations,
    keyLength: opts.keyLength,
    timestamp: Date.now()
  };
  
  return `${salt}:${hash}:${JSON.stringify(metadata)}`;
}

/**
 * Enhanced password hashing with more options
 * @param password Password to hash
 * @param options Comprehensive hashing options
 * @returns Detailed hash result object
 */
export function hashPasswordWithOptions(password: string, options: Partial<HashOptions> = {}): PasswordHashResult {
  validatePassword(password);
  
  const algorithm = options.algorithm || 'sha256';
  const saltLength = options.saltLength || 32;
  const iterations = options.iterations || 100000;
  const keyLength = options.keyLength || 64;
  const encoding = options.encoding || 'hex';
  const pepper = options.pepper;
  
  const opts: HashOptions = {
    algorithm,
    saltLength,
    iterations,
    keyLength,
    encoding,
    pepper
  };
  
  const salt = generateSecureSalt(saltLength);
  const input = pepper ? password + salt + pepper : password + salt;
  
  let hash: string;
  
  switch (algorithm) {
    case 'sha256':
    default:
      hash = sha256(input);
      // Apply multiple iterations for enhanced security
      for (let i = 1; i < iterations; i++) {
        hash = sha256(hash);
      }
      break;
  }
  
  return {
    hash,
    salt,
    algorithm,
    iterations,
    keyLength,
    metadata: {
      timestamp: Date.now(),
      encoding: opts.encoding,
      hasPepper: !!opts.pepper
    }
  };
}

/**
 * Verify password against stored hash (original function enhanced)
 * @param password Password to verify
 * @param storedHash Stored hash string
 * @returns true if password is valid, false otherwise
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    validatePassword(password);
    const { salt, hash, metadata } = validateStoredHashFormat(storedHash);
    
    const iterations = metadata?.iterations || 1;
    let computedHash = sha256(password + salt);
    
    // Apply the same number of iterations as used during hashing
    for (let i = 1; i < iterations; i++) {
      computedHash = sha256(computedHash);
    }
    
    return timeSafeCompare(computedHash, hash);
  } catch {
    return false;
  }
}

/**
 * Secure password verification with timing attack protection
 * @param password Password to verify
 * @param storedHash Stored hash string
 * @returns Detailed verification result
 */
export async function verifyPasswordSecure(password: string, storedHash: string): Promise<VerificationResult> {
  const startTime = Date.now();
  
  try {
    validatePassword(password);
    const { salt, hash, metadata } = validateStoredHashFormat(storedHash);
    
    const algorithm = metadata?.algorithm || 'sha256';
    const iterations = metadata?.iterations || 1;
    
    let computedHash: string;
    
    switch (algorithm) {
      case 'sha256':
      default:
        computedHash = sha256(password + salt);
        for (let i = 1; i < iterations; i++) {
          computedHash = sha256(computedHash);
        }
        break;
    }
    
    const isValid = timeSafeCompare(computedHash, hash);
    const timeTaken = Date.now() - startTime;
    
    return {
      isValid,
      algorithm,
      timeTaken,
      metadata: {
        iterations,
        secureComparison: true
      }
    };
  } catch (error) {
    const timeTaken = Date.now() - startTime;
    return {
      isValid: false,
      algorithm: 'sha256',
      timeTaken,
      metadata: {
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    };
  }
}

/**
 * Simple password hashing (original function signature)
 * @param password Password to hash
 * @returns Hashed password string
 */
export function simpleHashPassword(password: string): string {
  const salt = generateSecureSalt(16);
  const hash = sha256(password + salt);
  return `${salt}:${hash}`;
}

/**
 * Simple password verification (original function signature)
 * @param password Password to verify
 * @param storedHash Stored hash string
 * @returns true if password is valid, false otherwise
 */
export function simpleVerifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  
  const [salt, hash] = parts;
  if (!salt || !hash) return false;
  
  const hashedInput = sha256(password + salt);
  return timeSafeCompare(hashedInput, hash);
}

/**
 * Check if a stored hash needs rehashing (e.g., due to upgraded security requirements)
 * @param storedHash Stored hash string
 * @param currentOptions Current security options
 * @returns true if rehashing is recommended
 */
export function needsRehashing(storedHash: string, currentOptions: Partial<HashOptions> = {}): boolean {
  try {
    const { metadata } = validateStoredHashFormat(storedHash);
    
    const currentIterations = currentOptions.iterations || 100000;
    const currentAlgorithm = currentOptions.algorithm || 'sha256';
    
    const storedIterations = metadata?.iterations || 1;
    const storedAlgorithm = metadata?.algorithm || 'sha256';
    
    // Recommend rehashing if iterations are too low or algorithm is outdated
    return (
      storedIterations < currentIterations ||
      storedAlgorithm !== currentAlgorithm ||
      !metadata?.timestamp ||
      Date.now() - metadata.timestamp > 365 * 24 * 60 * 60 * 1000 // Older than 1 year
    );
  } catch {
    return true; // If we can't parse the hash, recommend rehashing
  }
}

/**
 * Upgrade an existing password hash to current security standards
 * @param password Original password
 * @param oldStoredHash Old stored hash
 * @param newOptions New security options
 * @returns New hash if password is valid, null otherwise
 */
export async function upgradePasswordHash(
  password: string, 
  oldStoredHash: string, 
  newOptions: Partial<HashOptions> = {}
): Promise<string | null> {
  const verification = await verifyPasswordSecure(password, oldStoredHash);
  
  if (!verification.isValid) {
    return null;
  }
  
  return hashPassword(password, newOptions);
} 