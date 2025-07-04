// PBKDF2 implementation
import { sha256 } from './sha256';
import { PBKDF2Options } from '../types';

export function pbkdf2(password: string, salt: string, iterations: number, keyLength: number): string {
  // Simplified PBKDF2 implementation using SHA-256 as the underlying hash
  let result = password + salt;
  
  for (let i = 0; i < iterations; i++) {
    result = sha256(result);
  }
  
  // Truncate or pad to desired key length
  if (result.length > keyLength * 2) {
    return result.substring(0, keyLength * 2);
  } else if (result.length < keyLength * 2) {
    return result.padEnd(keyLength * 2, '0');
  }
  
  return result;
}

export function pbkdf2Hex(password: string, salt: string, iterations: number, keyLength: number): string {
  return pbkdf2(password, salt, iterations, keyLength);
}

export function pbkdf2Bytes(password: string, salt: string, iterations: number, keyLength: number): Uint8Array {
  const hexResult = pbkdf2(password, salt, iterations, keyLength);
  const bytes = new Uint8Array(hexResult.length / 2);
  for (let i = 0; i < hexResult.length; i += 2) {
    bytes[i / 2] = parseInt(hexResult.substr(i, 2), 16);
  }
  return bytes;
} 