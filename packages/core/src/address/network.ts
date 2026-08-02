/** Bitcoin network parameters. Mainnet, testnet, signet, regtest only — Bitcoin, nothing else. */

export interface Network {
  name: "mainnet" | "testnet" | "signet" | "regtest";
  /** base58 version byte for P2PKH. */
  pubKeyHash: number;
  /** base58 version byte for P2SH. */
  scriptHash: number;
  /** bech32/bech32m human-readable part. */
  bech32: string;
}

export const MAINNET: Network = { name: "mainnet", pubKeyHash: 0x00, scriptHash: 0x05, bech32: "bc" };
export const TESTNET: Network = { name: "testnet", pubKeyHash: 0x6f, scriptHash: 0xc4, bech32: "tb" };
export const SIGNET: Network = { name: "signet", pubKeyHash: 0x6f, scriptHash: 0xc4, bech32: "tb" };
export const REGTEST: Network = { name: "regtest", pubKeyHash: 0x6f, scriptHash: 0xc4, bech32: "bcrt" };

export const NETWORKS = { mainnet: MAINNET, testnet: TESTNET, signet: SIGNET, regtest: REGTEST } as const;
export type NetworkName = keyof typeof NETWORKS;
