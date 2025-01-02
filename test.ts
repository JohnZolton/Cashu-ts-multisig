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
//import { hashToCurve, pointFromHex } from "@cashu/crypto/modules/common/index";
import { PrivKey, bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
//import { getSignedProofs } from "@cashu/crypto/modules/client/NUT11";
import { Proof, Secret, BlindSignature } from "@cashu/crypto/modules/common";
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
      tags,
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
  const MINT_URL = "https://testnut.cashu.space";
  const mint = new CashuMint(MINT_URL);
  const wallet = new CashuWallet(mint);
  await wallet.loadMint();

  const mintQuote = await wallet.createMintQuote(64);

  const proofs = await wallet.mintProofs(64, mintQuote.quote);

  console.log("ORIGINAL PROOFS: ", proofs);
  console.log("CREATING LOCKED ECASH");

  const amount = 32;

  const { keep, send } = await wallet.send(amount, proofs, {
    includeFees: true,
  });
  const feeAmount = wallet.getFeesForProofs(send);
  console.log(send);
  console.log("fees: ", feeAmount);

  const rawP2PKProofs = send.map((proof) =>
    createP2PKsecret({
      basePubkey: pubKey1,
      requiredSigs: 1,
      locktime: Math.floor(new Date().getTime() + 6 * 60 * 1000),
      refundPubkey: pubKey2,
      additionalPubkeys: [pubKey3],
    })
  );

  console.log(rawP2PKProofs);

  console.log(rawP2PKProofs);

  const p2pkProofs: Proof[] = send.map((proof, index) => ({
    ...proof,
    secret: rawP2PKProofs[index],
    C: pointFromBytes(rawP2PKProofs[index]), //convert Uint8 bytes array to projpoint type
  }));

  const signedProofs = getSignedProofs(p2pkProofs, bytesToHex(secKey1));

  console.log("Signed PRoofs:", signedProofs);
}

// Run the test
testP2PK().catch(console.error);
