// Security utilities and configurations
import { SECURITY_LEVELS, SecurityLevel, CryptoConfig } from '../types';
import { validatePassword, validateSaltStrength } from '../utils/validation';
import { generateSecureSalt } from '../utils/salt';

/**
 * Default security configuration
 */
export const DEFAULT_SECURITY_CONFIG: CryptoConfig = {
  defaultSaltLength: 32,
  defaultIterations: 100000,
  defaultKeyLength: 64,
  maxPasswordLength: 1024,
  minSaltLength: 16,
  maxSaltLength: 128,
  timingAttackProtection: true
};

/**
 * Get security level configuration
 * @param level Security level name
 * @returns Security level configuration
 */
export function getSecurityLevel(level: keyof typeof SECURITY_LEVELS): SecurityLevel {
  const securityLevel = SECURITY_LEVELS[level];
  if (!securityLevel) {
    throw new Error(`Invalid security level: ${level}`);
  }
  return securityLevel;
}

/**
 * Assess password strength
 * @param password Password to assess
 * @returns Strength assessment object
 */
export function assessPasswordStrength(password: string): {
  score: number;
  level: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  // Length check
  if (password.length >= 12) {
    score += 25;
  } else if (password.length >= 8) {
    score += 15;
  } else {
    feedback.push('Password should be at least 8 characters long');
  }

  // Character variety
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  const variety = [hasLower, hasUpper, hasNumbers, hasSpecial].filter(Boolean).length;
  score += variety * 15;

  if (!hasLower) feedback.push('Add lowercase letters');
  if (!hasUpper) feedback.push('Add uppercase letters');
  if (!hasNumbers) feedback.push('Add numbers');
  if (!hasSpecial) feedback.push('Add special characters');

  // Common patterns
  if (/(.)\1{2,}/.test(password)) {
    score -= 10;
    feedback.push('Avoid repeating characters');
  }

  if (/123|abc|qwe/i.test(password)) {
    score -= 15;
    feedback.push('Avoid common sequences');
  }

  // Determine level
  let level: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  if (score >= 80) level = 'very-strong';
  else if (score >= 60) level = 'strong';
  else if (score >= 40) level = 'good';
  else if (score >= 20) level = 'fair';
  else level = 'weak';

  return { score: Math.max(0, score), level, feedback };
}

/**
 * Generate a secure password
 * @param length Password length
 * @param includeSpecial Include special characters
 * @returns Generated password
 */
export function generateSecurePassword(length: number = 16, includeSpecial: boolean = true): string {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  let charset = lowercase + uppercase + numbers;
  if (includeSpecial) {
    charset += special;
  }

  let password = '';
  
  // Ensure at least one character from each category
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  
  if (includeSpecial) {
    password += special[Math.floor(Math.random() * special.length)];
  }

  // Fill remaining length
  for (let i = password.length; i < length; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }

  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

/**
 * Audit security configuration
 * @param config Security configuration to audit
 * @returns Audit results
 */
export function auditSecurityConfig(config: Partial<CryptoConfig>): {
  isSecure: boolean;
  warnings: string[];
  recommendations: string[];
} {
  const warnings: string[] = [];
  const recommendations: string[] = [];

  const saltLength = config.defaultSaltLength || DEFAULT_SECURITY_CONFIG.defaultSaltLength;
  const iterations = config.defaultIterations || DEFAULT_SECURITY_CONFIG.defaultIterations;
  const keyLength = config.defaultKeyLength || DEFAULT_SECURITY_CONFIG.defaultKeyLength;

  if (saltLength < 16) {
    warnings.push('Salt length is too short (minimum recommended: 16)');
  }

  if (iterations < 10000) {
    warnings.push('Iteration count is too low (minimum recommended: 10,000)');
  }

  if (keyLength < 32) {
    warnings.push('Key length is too short (minimum recommended: 32)');
  }

  if (!config.timingAttackProtection) {
    warnings.push('Timing attack protection is disabled');
  }

  // Recommendations
  if (iterations < 100000) {
    recommendations.push('Consider increasing iterations to 100,000 or more');
  }

  if (saltLength < 32) {
    recommendations.push('Consider increasing salt length to 32 bytes or more');
  }

  return {
    isSecure: warnings.length === 0,
    warnings,
    recommendations
  };
}

/**
 * Create a security profile for specific use cases
 * @param useCase Use case type
 * @returns Security configuration
 */
export function createSecurityProfile(useCase: 'web' | 'mobile' | 'enterprise' | 'api'): SecurityLevel {
  switch (useCase) {
    case 'web':
      return {
        iterations: 50000,
        saltLength: 24,
        keyLength: 48,
        algorithm: 'sha256'
      };
    case 'mobile':
      return {
        iterations: 25000,
        saltLength: 20,
        keyLength: 40,
        algorithm: 'sha256'
      };
    case 'enterprise':
      return {
        iterations: 200000,
        saltLength: 64,
        keyLength: 128,
        algorithm: 'sha512'
      };
    case 'api':
      return {
        iterations: 100000,
        saltLength: 32,
        keyLength: 64,
        algorithm: 'sha256'
      };
    default:
      return getSecurityLevel('medium');
  }
} 