/**
 * Minimal TypeScript declarations for snarkjs (the package ships no types).
 * Only the Groth16 functions this service uses are declared.
 */
declare module "snarkjs" {
  import type { Groth16Proof } from "./types.js";
  export namespace groth16 {
    function fullProve(
      input: Record<string, string>,
      wasmPath: string,
      zkeyPath: string
    ): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;
    function verify(
      vk: unknown,
      publicSignals: string[],
      proof: Groth16Proof
    ): Promise<boolean>;
  }
}
