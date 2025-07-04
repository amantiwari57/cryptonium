// Tests for password hashing functionality
import { hashPassword, verifyPassword, simpleHashPassword, simpleVerifyPassword } from '../src/core/password';
import { sha256 } from '../src/algorithms/sha256';

describe('Password Hashing', () => {
  describe('SHA-256', () => {
    test('should hash a message correctly', () => {
      const message = 'hello world';
      const expected = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      expect(sha256(message)).toBe(expected);
    });

    test('should handle empty string', () => {
      const result = sha256('');
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      expect(result.length).toBe(64);
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
      expect(hashedPassword.split(':').length).toBe(3); // salt:hash:metadata
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