import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "crypto";
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
import { hashToCurve, pointFromHex } from "@cashu/crypto/modules/common/index";

const secKey1 = generateSecretKey();
const secKey2 = generateSecretKey();
const secKey3 = generateSecretKey();
const pubKey1 = getPublicKey(secKey1);
const pubKey2 = getPublicKey(secKey2);
const pubKey3 = getPublicKey(secKey3);

// Types
type BlindedMessage = {
  id: string;
  amount: number;
  B_: string;
};

type BlindSignature = {
  amount: number;
  id: string;
  C_: string;
};

type Proof = {
  id: string;
  amount: number;
  secret: string;
  C: string;
  witness?: {
    signatures: string[];
  };
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0")) // Convert to hex and pad to 2 digits
    .join(""); // Concatenate all hex strings
}

class CashuMultiSig {
  static createMultiSigSecret(params: {
    basePubkey: string;
    requiredSigs: number;
    locktime: number;
    refundPubkey: string;
    additionalPubkeys: string[];
  }) {
    const secret = [
      "P2PK", //kind
      {
        nonce: randomBytes(32).toString("hex"), //unique random string
        data: params.basePubkey, //spend condition
        tags: [
          ["n_sigs", params.requiredSigs.toString()],
          ["locktime", params.locktime.toString()],
          ["refund", params.refundPubkey],
          ["pubkeys", ...params.additionalPubkeys],
        ],
      },
    ];
    return JSON.stringify(secret);
  }

  static createBlindedMessage(amount: number, keysetId: string) {
    let secret: Buffer = randomBytes(32);

    let point: ProjectivePoint | null = null;
    while (!point) {
      try {
        const hash = sha256(secret);
        const hashHex = bytesToHex(hash);
        const pointX = "02" + hashHex;
        point = ProjectivePoint.fromHex(pointX);
        break;
      } catch (error) {
        // If point creation fails, hash the previous attempt and try again
        secret = Buffer.from(sha256(secret));
      }
    }

    const Y = point;
    const r = BigInt("0x" + randomBytes(32).toString("hex"));
    const rG = ProjectivePoint.BASE.multiply(r);
    const B_ = Y.add(rG);

    return {
      blindedMessage: {
        amount,
        id: keysetId,
        B_: B_.toHex(true),
      },
      blindingFactor: r,
    };
  }

  static createProofFromBlindSignature(params: {
    amount: number;
    keysetId: string;
    mintPublicKey: ProjectivePoint;
    blindSignature: string;
    blindingFactor: bigint;
    secret: string;
  }) {
    const C_ = ProjectivePoint.fromHex(params.blindSignature);
    //const C_ = pointFromHex(params.blindSignature)
    const rK = params.mintPublicKey.multiply(params.blindingFactor);
    const C = C_.add(rK.negate());

    return {
      id: params.keysetId,
      amount: params.amount,
      secret: params.secret,
      C: C.toHex(true),
    };
  }
}

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
  const feeAmount = await wallet.getFeesForProofs(send);
  console.log(send);
  console.log("fees: ", feeAmount);

  const secret = CashuMultiSig.createMultiSigSecret({
    basePubkey: pubKey1,
    requiredSigs: 1,
    locktime: Math.floor(Date.now() / 1000 + 600), //10 minutes
    refundPubkey: pubKey2,
    additionalPubkeys: [pubKey1, pubKey2, pubKey3],
  });

  console.log("SECRET: ", secret);

  // a good way to fee swap would be nice...

  let remainingFee = feeAmount;
  const feeProofIndices: number[] = [];
  const spendableProofs = [...send];

  for (let i = 0; i < spendableProofs.length && remainingFee > 0; i++) {
    if (spendableProofs[i]!.amount <= remainingFee) {
      remainingFee -= spendableProofs[i]!.amount;
      feeProofIndices.push(i);
    }
  }
  const proofsForBlinding = spendableProofs.filter(
    (_, index) => !feeProofIndices.includes(index)
  );

  const { blindedMessages, blindingFactors } = proofsForBlinding.reduce(
    (acc, proof, index) => {
      const { blindedMessage, blindingFactor } =
        CashuMultiSig.createBlindedMessage(proof.amount, proof.id);
      return {
        blindedMessages: [...acc.blindedMessages, blindedMessage],
        blindingFactors: [...acc.blindingFactors, blindingFactor],
      };
    },
    {
      blindedMessages: [] as BlindedMessage[],
      blindingFactors: [] as bigint[],
    }
  );

  console.log("Blinded messages:", blindedMessages);

  console.log("Blinded messages:", blindedMessages);

  const response = await fetch(`${MINT_URL}/v1/swap`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ inputs: send, outputs: blindedMessages }),
  });

  interface MintResponse {
    signatures: BlindSignature[];
  }
  const { signatures } = (await response.json()) as MintResponse;
  console.log("REC'd SIGS: ", signatures);

  if (!signatures) return;

  const newProofs = signatures.map((signature, index) => {
    return CashuMultiSig.createProofFromBlindSignature({
      amount: signatures[index]?.amount ?? 0,
      keysetId: send[index]?.id ?? "",
      mintPublicKey: ProjectivePoint.fromHex(wallet.mintInfo.pubkey),
      blindSignature: signature.C_,
      blindingFactor: blindingFactors[index] ?? BigInt(1),
      secret,
    });
  });

  console.log("new proofs: ", newProofs);

  // FIRST SIG
  const firstSigs = await Promise.all(
    newProofs.map(async (proof) => {
      const messageHash = sha256(proof.secret);
      const signatureObj = schnorr.sign(messageHash, secKey1);
      const hexSignature = Buffer.from(signatureObj).toString("hex");
      console.log("sig obj hex: ", hexSignature);
      return hexSignature;
    })
  );
  console.log(signatures);

  const oneOfTwoSignedProofs = newProofs.map((proof, index) => ({
    ...proof,
    witness: { signatures: [firstSigs[index]] },
  }));

  const formattedProofs = oneOfTwoSignedProofs.map((proof) => ({
    ...proof,
    witness: JSON.stringify(proof.witness),
  }));

  console.log("TWO OF TWO SIGS: ", formattedProofs);
  // TODO exchange signed proofs for new
  const winnings = formattedProofs.reduce(
    (acc, proof) => acc + proof.amount,
    0
  );
  const fees = await wallet?.getFeesForProofs(formattedProofs);
  //ERROR COULD NOT VERIFY PROOFS
  const cleanProofs = await wallet?.swap(fees ? winnings - fees : 0, [
    ...proofs,
    ...formattedProofs,
  ]);

  console.log("CLEAN PROOFS:", cleanProofs);
}

// Run the test
testP2PK().catch(console.error);
