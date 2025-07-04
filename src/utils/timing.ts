// Timing-safe comparison utilities to prevent timing attacks

/**
 * Performs a constant-time string comparison to prevent timing attacks
 * @param a First string to compare
 * @param b Second string to compare
 * @returns true if strings are equal, false otherwise
 */
export function timeSafeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  // Convert strings to byte arrays using Buffer
  const aBytes = Buffer.from(a, 'utf8');
  const bBytes = Buffer.from(b, 'utf8');

  // Always compare the same number of bytes to prevent timing attacks
  const maxLength = Math.max(aBytes.length, bBytes.length);
  let result = aBytes.length ^ bBytes.length; // XOR lengths

  // Compare each byte position, even if lengths differ
  for (let i = 0; i < maxLength; i++) {
    const aByte = i < aBytes.length ? aBytes[i] : 0;
    const bByte = i < bBytes.length ? bBytes[i] : 0;
    result |= aByte ^ bByte;
  }

  return result === 0;
}

/**
 * Alternative constant-time comparison using buffer comparison
 * @param a First string to compare
 * @param b Second string to compare
 * @returns true if strings are equal, false otherwise
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (a.length !== b.length) {
    // Still perform a comparison to maintain constant time
    timeSafeCompare(a, a);
    return false;
  }

  return timeSafeCompare(a, b);
}

/**
 * Adds artificial delay to prevent timing analysis
 * @param minTime Minimum time in milliseconds
 */
export async function addTimingDelay(minTime: number = 10): Promise<void> {
  const startTime = Date.now();
  
  // Perform some CPU-intensive work
  let dummy = 0;
  for (let i = 0; i < 1000; i++) {
    dummy += Math.random();
  }
  
  const elapsed = Date.now() - startTime;
  const remainingTime = Math.max(0, minTime - elapsed);
  
  if (remainingTime > 0) {
    await new Promise(resolve => setTimeout(resolve, remainingTime));
  }
}

/**
 * Measures execution time of a function
 * @param fn Function to measure
 * @returns Object containing result and execution time
 */
export async function measureExecutionTime<T>(
  fn: () => T | Promise<T>
): Promise<{ result: T; timeMs: number }> {
  const startTime = process.hrtime.bigint();
  const result = await fn();
  const endTime = process.hrtime.bigint();
  const timeMs = Number(endTime - startTime) / 1000000; // Convert nanoseconds to milliseconds
  
  return { result, timeMs };
}

/**
 * Secure comparison with timing attack protection and artificial delay
 * @param a First string to compare
 * @param b Second string to compare
 * @param minTime Minimum comparison time in milliseconds
 * @returns true if strings are equal, false otherwise
 */
export async function secureCompare(
  a: string, 
  b: string, 
  minTime: number = 50
): Promise<boolean> {
  const startTime = Date.now();
  
  const isEqual = timeSafeCompare(a, b);
  
  const elapsed = Date.now() - startTime;
  const remainingTime = Math.max(0, minTime - elapsed);
  
  if (remainingTime > 0) {
    await new Promise(resolve => setTimeout(resolve, remainingTime));
  }
  
  return isEqual;
}

/**
 * Validates that comparison took a reasonable amount of time
 * @param startTime Start time in milliseconds
 * @param minTime Minimum expected time
 * @param maxTime Maximum expected time
 * @returns true if timing is within expected range
 */
export function validateComparisonTiming(
  startTime: number, 
  minTime: number = 10, 
  maxTime: number = 5000
): boolean {
  const elapsed = Date.now() - startTime;
  return elapsed >= minTime && elapsed <= maxTime;
} 