const NFT_ID_LEN = 36;
const NFT_CODE_HASH_LEN = 20;
const NFT_ID_OFFSET = 0 + NFT_ID_LEN;
const NFT_CODE_HASH_OFFSET = NFT_ID_OFFSET + NFT_CODE_HASH_LEN;
export function getNftID(script: Buffer) {
  return script.slice(
    script.length - NFT_ID_OFFSET,
    script.length - NFT_ID_OFFSET + NFT_ID_LEN
  );
}

export function getNftCodehHash(script: Buffer) {
  return script.slice(
    script.length - NFT_CODE_HASH_OFFSET,
    script.length - NFT_CODE_HASH_OFFSET + NFT_CODE_HASH_LEN
  );
}

export type FormatedDataPart = {
  nftID: string;
  nftCodeHash: string;
};

export function newDataPart(dataPart: FormatedDataPart): Buffer {
  let nftCodeHashBuf = Buffer.from(dataPart.nftCodeHash, "hex");
  let nftIDBuf = Buffer.from(dataPart.nftID, "hex");
  return Buffer.concat([nftCodeHashBuf, nftIDBuf]);
}

export function parseDataPart(scriptBuf: Buffer): FormatedDataPart {
  let nftID = getNftID(scriptBuf).toString("hex");
  let nftCodeHash = getNftCodehHash(scriptBuf).toString("hex");
  return {
    nftID,
    nftCodeHash,
  };
}
