// Type definitions for Cryptonium

export type HashAlgorithm = 'sha256' | 'sha512' | 'pbkdf2';
export type Encoding = 'hex' | 'base64' | 'binary';
export type SaltStrategy = 'random' | 'crypto' | 'secure';

export interface HashOptions {
  algorithm?: HashAlgorithm;
  saltLength?: number;
  iterations?: number;
  keyLength?: number;
  encoding?: Encoding;
  pepper?: string;
}

export interface PasswordHashResult {
  hash: string;
  salt: string;
  algorithm: HashAlgorithm;
  iterations?: number;
  keyLength?: number;
  metadata?: Record<string, any>;
}

export interface VerificationResult {
  isValid: boolean;
  algorithm: HashAlgorithm;
  timeTaken: number;
  metadata?: Record<string, any>;
}

export interface PBKDF2Options {
  iterations: number;
  keyLength: number;
  salt: string | Uint8Array;
  algorithm?: 'sha256' | 'sha512';
}

export interface HMACOptions {
  key: string | Uint8Array;
  algorithm?: 'sha256' | 'sha512';
  encoding?: Encoding;
}

export interface SaltOptions {
  length: number;
  strategy?: SaltStrategy;
  charset?: string;
}

export interface TimingAttackResistantComparison {
  (a: string, b: string): boolean;
}

export interface CryptoConfig {
  defaultSaltLength: number;
  defaultIterations: number;
  defaultKeyLength: number;
  maxPasswordLength: number;
  minSaltLength: number;
  maxSaltLength: number;
  timingAttackProtection: boolean;
}

export interface SecurityLevel {
  iterations: number;
  saltLength: number;
  keyLength: number;
  algorithm: HashAlgorithm;
}

export const SECURITY_LEVELS: Record<string, SecurityLevel> = {
  low: {
    iterations: 10000,
    saltLength: 16,
    keyLength: 32,
    algorithm: 'sha256'
  },
  medium: {
    iterations: 50000,
    saltLength: 24,
    keyLength: 48,
    algorithm: 'sha256'
  },
  high: {
    iterations: 100000,
    saltLength: 32,
    keyLength: 64,
    algorithm: 'sha512'
  },
  maximum: {
    iterations: 500000,
    saltLength: 64,
    keyLength: 128,
    algorithm: 'pbkdf2'
  }
};

export class CryptoniumError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'CryptoniumError';
  }
}

export class ValidationError extends CryptoniumError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR');
  }
}

export class SecurityError extends CryptoniumError {
  constructor(message: string) {
    super(message, 'SECURITY_ERROR');
  }
} 