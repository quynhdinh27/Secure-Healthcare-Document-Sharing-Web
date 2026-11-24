// Argon2id provider cho backup khóa (README crypto module: deriveArgon2id(password, salt, profile) → 32 bytes).
import { argon2id } from 'hash-wasm';

export const deriveArgon2id = (password, salt, profile) => argon2id({
  password,
  salt,
  memorySize: profile.memoryKiB,
  iterations: profile.iterations,
  parallelism: profile.parallelism,
  hashLength: profile.length,
  outputType: 'binary',
});
