// Input validation utilities for security
import { ValidationError } from '../types';

/**
 * Validates password input
 */
export function validatePassword(password: string): void {
  if (typeof password !== 'string') {
    throw new ValidationError('Password must be a string');
  }
  
  if (password.length === 0) {
    throw new ValidationError('Password cannot be empty');
  }
  
  if (password.length > 1024) {
    throw new ValidationError('Password is too long (max 1024 characters)');
  }
  
  // Check for null bytes which could cause issues
  if (password.includes('\0')) {
    throw new ValidationError('Password cannot contain null bytes');
  }
}

/**
 * Validates salt input
 */
export function validateSalt(salt: string, minLength: number = 8, maxLength: number = 128): void {
  if (typeof salt !== 'string') {
    throw new ValidationError('Salt must be a string');
  }
  
  if (salt.length < minLength) {
    throw new ValidationError(`Salt must be at least ${minLength} characters long`);
  }
  
  if (salt.length > maxLength) {
    throw new ValidationError(`Salt must be at most ${maxLength} characters long`);
  }
}

/**
 * Validates hash input
 */
export function validateHash(hash: string): void {
  if (typeof hash !== 'string') {
    throw new ValidationError('Hash must be a string');
  }
  
  if (hash.length === 0) {
    throw new ValidationError('Hash cannot be empty');
  }
  
  // Check for valid hex characters
  if (!/^[a-fA-F0-9]+$/.test(hash)) {
    throw new ValidationError('Hash must contain only hexadecimal characters');
  }
}

/**
 * Validates iterations for PBKDF2
 */
export function validateIterations(iterations: number): void {
  if (!Number.isInteger(iterations)) {
    throw new ValidationError('Iterations must be an integer');
  }
  
  if (iterations < 1000) {
    throw new ValidationError('Iterations must be at least 1000 for security');
  }
  
  if (iterations > 10000000) {
    throw new ValidationError('Iterations cannot exceed 10,000,000');
  }
}

/**
 * Validates key length
 */
export function validateKeyLength(keyLength: number): void {
  if (!Number.isInteger(keyLength)) {
    throw new ValidationError('Key length must be an integer');
  }
  
  if (keyLength < 8) {
    throw new ValidationError('Key length must be at least 8 bytes');
  }
  
  if (keyLength > 512) {
    throw new ValidationError('Key length cannot exceed 512 bytes');
  }
}

/**
 * Validates stored hash format
 */
export function validateStoredHashFormat(storedHash: string): { salt: string; hash: string; metadata?: any } {
  if (typeof storedHash !== 'string') {
    throw new ValidationError('Stored hash must be a string');
  }
  
  const parts = storedHash.split(':');
  
  if (parts.length < 2) {
    throw new ValidationError('Invalid stored hash format - must contain salt and hash separated by colon');
  }
  
  const salt = parts[0];
  const hash = parts[1];
  const metadataParts = parts.slice(2);
  
  if (!salt || !hash) {
    throw new ValidationError('Invalid stored hash format - salt and hash cannot be empty');
  }
  
  validateSalt(salt);
  validateHash(hash);
  
  let metadata;
  if (metadataParts.length > 0) {
    try {
      metadata = JSON.parse(metadataParts.join(':'));
    } catch {
      // Metadata is optional and can be ignored if invalid
    }
  }
  
  return { salt, hash, metadata };
}

/**
 * Sanitizes string input to prevent injection attacks
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') {
    throw new ValidationError('Input must be a string');
  }
  
  // Remove null bytes and other potentially dangerous characters
  return input.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, '');
}

/**
 * Validates encoding type
 */
export function validateEncoding(encoding: string): void {
  const validEncodings = ['hex', 'base64', 'binary'];
  if (!validEncodings.includes(encoding)) {
    throw new ValidationError(`Invalid encoding. Must be one of: ${validEncodings.join(', ')}`);
  }
} 