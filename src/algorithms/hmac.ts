// HMAC implementation
import { sha256 } from './sha256';
import { HMACOptions } from '../types';

export function hmac(message: string, key: string): string {
  // Simplified HMAC implementation using SHA-256
  const blockSize = 64; // SHA-256 block size in bytes
  
  // Pad or truncate key to block size
  let paddedKey = key;
  if (key.length > blockSize) {
    paddedKey = sha256(key).substring(0, blockSize * 2);
  } else {
    paddedKey = key.padEnd(blockSize * 2, '0');
  }
  
  // Create inner and outer padding
  const innerPad = '36'.repeat(blockSize);
  const outerPad = '5c'.repeat(blockSize);
  
  // XOR key with padding
  let innerKey = '';
  let outerKey = '';
  
  for (let i = 0; i < paddedKey.length; i += 2) {
    const keyByte = parseInt(paddedKey.substr(i, 2), 16);
    const innerByte = keyByte ^ 0x36;
    const outerByte = keyByte ^ 0x5c;
    innerKey += innerByte.toString(16).padStart(2, '0');
    outerKey += outerByte.toString(16).padStart(2, '0');
  }
  
  // HMAC = H(outerKey || H(innerKey || message))
  const innerHash = sha256(innerKey + message);
  return sha256(outerKey + innerHash);
}

export function hmacWithOptions(message: string, options: HMACOptions): string {
  const key = typeof options.key === 'string' ? options.key : Buffer.from(options.key).toString('hex');
  return hmac(message, key);
} 