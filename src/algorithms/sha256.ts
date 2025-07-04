// Enhanced SHA-256 implementation
export function sha256(message: string): string {
  // Utility functions for bitwise operations
  const rightRotate = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;
  const rightShift = (x: number, n: number): number => x >>> n;

  // SHA-256 constants
  const K: number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  // Initial hash values
  const H0: number[] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

  function stringToWords(str: string): number[] {
    const bytes: Uint8Array = new TextEncoder().encode(str);
    const words: number[] = [];
    for (let i = 0; i < bytes.length; i += 4) {
      let word = 0;
      for (let j = 0; j < 4 && i + j < bytes.length; j++) {
        word = (word << 8) + bytes[i + j];
      }
      words.push(word >>> 0);
    }
    return words;
  }

  // Pre-processing: padding
  const msgWords: number[] = stringToWords(message);
  const bitLength: number = message.length * 8;
  msgWords.push(0x80000000);
  while ((msgWords.length % 16) !== 14) msgWords.push(0);
  msgWords.push(Math.floor(bitLength / 0x100000000));
  msgWords.push(bitLength >>> 0);

  // Initialize hash values
  let h: number[] = [...H0];

  // Process message in 512-bit chunks
  for (let i = 0; i < msgWords.length; i += 16) {
    const w: number[] = msgWords.slice(i, i + 16).concat(new Array(48).fill(0));
    for (let t = 16; t < 64; t++) {
      const s0: number = rightRotate(w[t - 15], 7) ^ rightRotate(w[t - 15], 18) ^ rightShift(w[t - 15], 3);
      const s1: number = rightRotate(w[t - 2], 17) ^ rightRotate(w[t - 2], 19) ^ rightShift(w[t - 2], 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h0] = h;
    for (let t = 0; t < 64; t++) {
      const S1: number = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch: number = (e & f) ^ (~e & g);
      const temp1: number = (h0 + S1 + ch + K[t] + w[t]) >>> 0;
      const S0: number = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj: number = (a & b) ^ (a & c) ^ (b & c);
      const temp2: number = (S0 + maj) >>> 0;

      h0 = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h = h.map((val, idx) => (val + [a, b, c, d, e, f, g, h0][idx]) >>> 0);
  }

  return h.map((x) => x.toString(16).padStart(8, "0")).join("");
}

export function sha256Hex(message: string): string {
  return sha256(message);
}

export function sha256Bytes(message: string): Uint8Array {
  const hexHash = sha256(message);
  const bytes = new Uint8Array(hexHash.length / 2);
  for (let i = 0; i < hexHash.length; i += 2) {
    bytes[i / 2] = parseInt(hexHash.substr(i, 2), 16);
  }
  return bytes;
} 