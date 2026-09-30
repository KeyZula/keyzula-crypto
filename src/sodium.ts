import sodiumModule from "libsodium-wrappers-sumo";

export type Sodium = typeof sodiumModule;

let initialized = false;

/** Loads the libsodium WASM module. Call once at startup; all other functions are synchronous. */
export async function initCrypto(): Promise<void> {
  if (initialized) return;
  await sodiumModule.ready;
  initialized = true;
}

export function sodium(): Sodium {
  if (!initialized) {
    throw new Error("Crypto not initialized: call initCrypto() first.");
  }
  return sodiumModule;
}
