import { sha256 } from "@noble/hashes/sha256";
import { randomBytes, sign } from "crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { generateSecretKey, getPublicKey } from "nostr-tools";
import { ProjectivePoint } from "@noble/secp256k1";
import {
  CashuMint,
  CashuWallet,
  getEncodedTokenV4,
  MintQuoteState,
  MintPayload,
  MintKeys,
} from "@cashu/cashu-ts";
import { pointFromHex } from "@cashu/crypto/modules/common";
import { PrivKey, bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
//import { getSignedProofs } from "@cashu/crypto/modules/client/NUT11";

import {
  Proof,
  Secret,
  BlindSignature,
  hashToCurve,
} from "@cashu/crypto/modules/common";
import {
  BlindedMessage,
  blindMessage,
  createRandomBlindedMessage,
} from "@cashu/crypto/modules/client";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { pointFromBytes } from "@cashu/crypto/modules/common";

export const parseSecret = (secret: string | Uint8Array): Secret => {
  try {
    if (secret instanceof Uint8Array) {
      secret = new TextDecoder().decode(secret);
    }
    return JSON.parse(secret);
  } catch (e) {
    throw new Error("can't parse secret");
  }
};

export const signP2PKsecret = (secret: Uint8Array, privateKey: PrivKey) => {
  const msghash = sha256(new TextDecoder().decode(secret));
  const sig = schnorr.sign(msghash, privateKey);
  return sig;
};

export const signBlindedMessage = (
  B_: string,
  privateKey: PrivKey
): Uint8Array => {
  const msgHash = sha256(B_);
  const sig = schnorr.sign(msgHash, privateKey);
  return sig;
};
export const hexToString = (hexSecret: string) => {
  try {
    const buffer = Buffer.from(hexSecret, "hex");
    return buffer.toString("utf-8");
  } catch (error) {
    throw new Error("Invalid hex string");
  }
};

export const getSignedProofs = (
  proofs: Array<Proof>,
  privateKey: string
): Array<Proof> => {
  return proofs.map((p) => {
    try {
      const parsed: Secret = parseSecret(p.secret);
      if (parsed[0] !== "P2PK") {
        throw new Error("unknown secret type");
      }
      return getSignedProof(p, hexToBytes(privateKey));
    } catch (error) {
      return p;
    }
  });
};

export const getSignedOutput = (
  output: BlindedMessage,
  privateKey: PrivKey
): BlindedMessage => {
  const B_ = output.B_.toHex(true);
  const signature = signBlindedMessage(B_, privateKey);
  output.witness = { signatures: [bytesToHex(signature)] };
  return output;
};

export const getSignedOutputs = (
  outputs: Array<BlindedMessage>,
  privateKey: string
): Array<BlindedMessage> => {
  return outputs.map((o) => getSignedOutput(o, privateKey));
};

export const getSignedProof = (proof: Proof, privateKey: PrivKey): Proof => {
  if (!proof.witness) {
    proof.witness = {
      signatures: [bytesToHex(signP2PKsecret(proof.secret, privateKey))],
    };
  }
  return proof;
};

export const createP2PKsecret = (params: {
  basePubkey: string;
  requiredSigs?: number;
  locktime?: number;
  refundPubkey?: string;
  additionalPubkeys?: string[];
}): Uint8Array => {
  const tags: Array<[string, ...string[]]> = [];

  if (params.requiredSigs !== undefined) {
    tags.push(["n_sigs", params.requiredSigs.toString()]);
  }
  if (params.locktime !== undefined) {
    tags.push(["locktime", params.locktime.toString()]);
  }
  if (params.refundPubkey !== undefined) {
    tags.push(["refund", params.refundPubkey]);
  }
  if (params.additionalPubkeys?.length) {
    tags.push(["pubkeys", ...params.additionalPubkeys]);
  }

  const secret: Secret = [
    "P2PK", //kind
    {
      nonce: bytesToHex(randomBytes(32)),
      data: params.basePubkey, //spend condition
      tags: tags,
    },
  ];
  const parsed = JSON.stringify(secret);
  return new TextEncoder().encode(parsed);
};

const secKey1 = generateSecretKey();
const secKey2 = generateSecretKey();
const secKey3 = generateSecretKey();
const pubKey1 = getPublicKey(secKey1);
const pubKey2 = getPublicKey(secKey2);
const pubKey3 = getPublicKey(secKey3);

console.log(pubKey1);
console.log(pubKey2);
console.log(pubKey3);

type ProofObj = {
  id: string;
  amount: number;
  secret: string;
  C: string;
  witness?: {
    signatures: string[];
  };
};

// Test function
async function testP2PK() {
  const MINT_URL = "http://0.0.0.0:3338";
  const mint = new CashuMint(MINT_URL);
  const wallet = new CashuWallet(mint);
  await wallet.loadMint();

  const mintQuote = await wallet.createMintQuote(64);

  const proofs = await wallet.mintProofs(64, mintQuote.quote);

  const amount = 32;

  const { keep, send } = await wallet.send(amount, proofs, {
    includeFees: true,
  });
  const feeAmount = wallet.getFeesForProofs(send);
  console.log("fees: ", feeAmount);

  console.log("CREATING LOCKED ECASH");
  const rawP2PKProofs = send.map(() =>
    createP2PKsecret({
      basePubkey: pubKey2,
      requiredSigs: 1,
      locktime: Math.floor(new Date().getTime() + 6 * 60 * 1000),
      refundPubkey: pubKey1,
      additionalPubkeys: [pubKey1, pubKey2, pubKey3],
    })
  );

  console.log(rawP2PKProofs);

  const p2pkProofs: Proof[] = send.map((proof, index) => ({
    ...proof,
    secret: rawP2PKProofs[index],
    C: pointFromHex(proof.C),
  }));

  const signedProofs = getSignedProofs(p2pkProofs, bytesToHex(secKey1));

  console.log("Signed PRoofs:", signedProofs);

  const convertedProofs = signedProofs.map((proof) => ({
    ...proof,
    secret: hexToString(bytesToHex(proof.secret)),
    C: proof.C.toHex(true),
    witness: JSON.stringify(proof.witness),
  }));

  console.log("converted: ", convertedProofs);

  try {
    const redeemedProofs = await wallet.swap(30, convertedProofs);
    console.log("redeemed: ", redeemedProofs);
  } catch (error: unknown) {
    if (typeof error === "object" && error !== null) {
      console.error("Error obj details:");
      const errorObj = error as Record<string, any>;
      for (const key in errorObj) {
        if (Object.prototype.hasOwnProperty.call(error, key)) {
          console.error(`  ${key}:`, errorObj[key]);
        }
      }
    } else {
      console.error("error: ", error);
    }
  }
}

// Run the test
testP2PK().catch(console.error);
