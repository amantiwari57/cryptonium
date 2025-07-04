// Tests for password hashing functionality
import { hashPassword, verifyPassword, simpleHashPassword, simpleVerifyPassword } from '../src/core/password';
import { sha256 } from '../src/algorithms/sha256';

describe('Password Hashing', () => {
  describe('SHA-256', () => {
    test('should hash a message consistently', () => {
      const message = 'hello world';
      const hash1 = sha256(message);
      const hash2 = sha256(message);
      
      expect(hash1).toBeDefined();
      expect(typeof hash1).toBe('string');
      expect(hash1.length).toBe(64);
      expect(hash1).toBe(hash2); // Should be consistent
    });

    test('should handle empty string', () => {
      const result = sha256('');
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);
    });
    
    test('should produce different hashes for different inputs', () => {
      const hash1 = sha256('hello');
      const hash2 = sha256('world');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Simple Password Functions', () => {
    test('should hash and verify password correctly', () => {
      const password = 'testpassword123';
      const hashedPassword = simpleHashPassword(password);
      
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword.includes(':')).toBe(true);
      
      const isValid = simpleVerifyPassword(password, hashedPassword);
      expect(isValid).toBe(true);
      
      const isInvalid = simpleVerifyPassword('wrongpassword', hashedPassword);
      expect(isInvalid).toBe(false);
    });

    test('should reject invalid hash format', () => {
      const password = 'testpassword123';
      const invalidHash = 'invalidhashformat';
      
      const isValid = simpleVerifyPassword(password, invalidHash);
      expect(isValid).toBe(false);
    });
  });

  describe('Enhanced Password Functions', () => {
    test('should hash password with options', () => {
      const password = 'testpassword123';
      const hashedPassword = hashPassword(password, { iterations: 1000 });
      
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword.includes(':')).toBe(true);
      
      // Should have at least salt and hash parts
      const parts = hashedPassword.split(':');
      expect(parts.length).toBeGreaterThanOrEqual(2);
    });

    test('should verify password with metadata', () => {
      const password = 'testpassword123';
      const hashedPassword = hashPassword(password, { iterations: 1000 });
      
      const isValid = verifyPassword(password, hashedPassword);
      expect(isValid).toBe(true);
      
      const isInvalid = verifyPassword('wrongpassword', hashedPassword);
      expect(isInvalid).toBe(false);
    });
  });
}); 