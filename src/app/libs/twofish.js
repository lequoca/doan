// twofish.js

// GF(2^8) multiplication
export function gfMul(a, b, p) {
    let r = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 0x01) {
        r ^= a;
      }
      const highBit = a & 0x80;
      a = (a << 1) & 0xFF;
      if (highBit) a ^= p;
      b >>= 1;
    }
    return r >>> 0;
  }
  
  const ROUND_SUBKEYS = 20;
  const ROUNDS = 16;
  const SK_STEP = 0x02020202;
  const SK_BUMP = 0x01010101;
  const SK_ROTL = 9;
  
  const P0 = [/*...*/]; // Thay bằng nội dung của P0
  const P1 = [/*...*/]; // Thay bằng nội dung của P1
  const P = [P0, P1];
  
  const MDS = (() => {
    const mxX = (x) => x ^ (x >> 2) ^ (x >> 1);
    const mxY = (x) => x ^ (x >> 1) ^ (x >> 2);
    const localMDS = [[], [], [], []];
    for (let i = 0; i < 256; i++) {
      localMDS[0][i] = i ^ mxX(i);
      localMDS[1][i] = i ^ mxY(i);
      localMDS[2][i] = mxX(i);
      localMDS[3][i] = mxY(i);
    }
    return localMDS;
  })();
  
  const b0 = (x) => x & 0xFF;
  const b1 = (x) => (x >>> 8) & 0xFF;
  const b2 = (x) => (x >>> 16) & 0xFF;
  const b3 = (x) => (x >>> 24) & 0xFF;
  
  // Rotate functions
  export function rotateLeft32(value, shift) {
    return (value << shift) | (value >>> (32 - shift));
  }
  
  export function rotateRight32(value, shift) {
    return (value >>> shift) | (value << (32 - shift));
  }
  
  // Key expansion
  export function keyExpansion(aKey) {
    if (!Array.isArray(aKey)) {
      throw new Error("Key must be an array");
    }
  
    let keyLength = aKey.length;
    const k64Cnt = Math.ceil(keyLength / 8);
    const subKeyCnt = ROUND_SUBKEYS + 2 * ROUNDS;
    const k32e = new Array(4).fill(0);
    const k32o = new Array(4).fill(0);
    const sBoxKey = new Array(4).fill(0);
  
    // Pad or truncate key
    if (keyLength < 8 || (keyLength > 8 && keyLength < 16) ||
        (keyLength > 16 && keyLength < 24) || keyLength > 32) {
      aKey = Array.from(aKey).concat(new Array(32 - keyLength).fill(0)).slice(0, 32);
    }
  
    let offset = 0;
    for (let i = 0; i < 4; i++) {
      if (offset >= keyLength) break;
      k32e[i] = (aKey[offset++] & 0xFF) |
                ((aKey[offset++] & 0xFF) << 8) |
                ((aKey[offset++] & 0xFF) << 16) |
                ((aKey[offset++] & 0xFF) << 24);
      k32o[i] = (aKey[offset++] & 0xFF) |
                ((aKey[offset++] & 0xFF) << 8) |
                ((aKey[offset++] & 0xFF) << 16) |
                ((aKey[offset++] & 0xFF) << 24);
      sBoxKey[3 - i] = k32e[i] ^ k32o[i]; // Giả sử thuật toán rsMDSEncode
    }
  
    const subKeys = [];
    for (let i = 0, q = 0; i < subKeyCnt / 2; i++, q += SK_STEP) {
      const A = k32e[0]; // Giả định f32 đơn giản hóa
      const B = k32o[0];
      subKeys[2 * i] = A + B;
      subKeys[2 * i + 1] = ((A + 2 * B) << SK_ROTL) | ((A + 2 * B) >>> (32 - SK_ROTL));
    }
  
    return [sBoxKey, subKeys];
  }
  
  export function twofishEncrypt(key, input) {
    const [sBoxKey, subKeys] = keyExpansion(key);
  
    const inputBlock = new Uint32Array(input);
    const encryptedBlock = new Uint32Array(4);
    // Giả lập block encrypt cơ bản
    for (let i = 0; i < 4; i++) {
      encryptedBlock[i] = inputBlock[i] ^ subKeys[i];
    }
    return Array.from(encryptedBlock);
  }
  
  export function twofishDecrypt(key, input) {
    const [sBoxKey, subKeys] = keyExpansion(key);
  
    const inputBlock = new Uint32Array(input);
    const decryptedBlock = new Uint32Array(4);
    // Giả lập block decrypt cơ bản
    for (let i = 0; i < 4; i++) {
      decryptedBlock[i] = inputBlock[i] ^ subKeys[i];
    }
    return Array.from(decryptedBlock);
  }
  