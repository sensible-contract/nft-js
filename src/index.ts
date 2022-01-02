import { Provider } from "@sensible-contract/abstract-provider";
import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  getRabinData,
  getRabinDatas,
  getZeroAddress,
  PLACE_HOLDER_PUBKEY,
  PLACE_HOLDER_SIG,
  Prevouts,
  SatotxSigner,
  selectSigners,
  SignerConfig,
  SizeTransaction,
  Utils,
} from "@sensible-contract/sdk-core";
import {
  Bytes,
  Int,
  PubKey,
  Ripemd160,
  Sig,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import { TxComposer } from "@sensible-contract/tx-composer";
import { NftFactory } from "./contract-factory/nft";
import { NftGenesis, NftGenesisFactory } from "./contract-factory/nftGenesis";
import {
  NftUnlockContractCheckFactory,
  NFT_UNLOCK_CONTRACT_TYPE,
} from "./contract-factory/nftUnlockContractCheck";
import * as nftProto from "./contract-proto/nft.proto";
import { ContractUtil } from "./contractUtil";

const Signature = bsv.crypto.Signature;
export const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID;

export type NftMetaData = {
  name?: string;
  description?: string;
  image?: string;
  tokenUri?: string;
} & { [x: string]: any };

type ParamNftUtxo = {
  txId: string;
  outputIndex: number;
  tokenAddress: string;
  tokenIndex: string;
};

export type NftInput = {
  txId: string;
  outputIndex: number;
  satoshis?: number;
  lockingScript?: bsv.Script;

  satotxInfo?: {
    txId: string;
    outputIndex: number;
    txHex: string;
    preTxId: string;
    preOutputIndex: number;
    preTxHex: string;
  };

  nftAddress?: bsv.Address;
  preNftAddress?: bsv.Address;
  preLockingScript?: bsv.Script;

  rabinPubKeyHashArrayHash?: string;
  nftID?: string;
  publicKey?: bsv.PublicKey;
  inputIndex?: number;

  codehash?: string;
  genesis?: string;
  sensibleID?: {
    txid: string;
    index: number;
  };
  tokenIndex?: string;
};

export type NftGenesisInput = {
  txId: string;
  outputIndex: number;
  satoshis?: number;
  lockingScript?: bsv.Script;

  satotxInfo?: {
    txId: string;
    outputIndex: number;
    txHex: string;
    preTxId: string;
    preOutputIndex: number;
    preTxHex: string;
  };

  nftCodehash?: string;
  nftGenesis?: string;
  publicKey?: string;
  sensibleID?: {
    txid: string;
    index: number;
  };
  rabinPubKeyHashArrayHash?: string;

  totalSupply?: BN;
};

export type ParamUtxo = {
  txId: string;
  outputIndex: number;
  satoshis: number;
  address: string;
};
export const defaultSignerConfigs: SignerConfig[] = [
  {
    satotxApiPrefix: "https://s1.satoplay.cn,https://s1.satoplay.com",
    satotxPubKey:
      "2c8c0117aa5edba9a4539e783b6a1bdbc1ad88ad5b57f3d9c5cba55001c45e1fedb877ebc7d49d1cfa8aa938ccb303c3a37732eb0296fee4a6642b0ff1976817b603404f64c41ec098f8cd908caf64b4a3aada220ff61e252ef6d775079b69451367eda8fdb37bc55c8bfd69610e1f31b9d421ff44e3a0cfa7b11f334374827256a0b91ce80c45ffb798798e7bd6b110134e1a3c3fa89855a19829aab3922f55da92000495737e99e0094e6c4dbcc4e8d8de5459355c21ff055d039a202076e4ca263b745a885ef292eec0b5a5255e6ecc45534897d9572c3ebe97d36626c7b1e775159e00b17d03bc6d127260e13a252afd89bab72e8daf893075f18c1840cb394f18a9817913a9462c6ffc8951bee50a05f38da4c9090a4d6868cb8c955e5efb4f3be4e7cf0be1c399d78a6f6dd26a0af8492dca67843c6da9915bae571aa9f4696418ab1520dd50dd05f5c0c7a51d2843bd4d9b6b3b79910e98f3d98099fd86d71b2fac290e32bdacb31943a8384a7668c32a66be127b74390b4b0dec6455",
  },
  {
    satotxApiPrefix: "https://satotx.showpay.top",
    satotxPubKey:
      "5b94858991d384c61ffd97174e895fcd4f62e4fea618916dc095fe4c149bbdf1188c9b33bc15cbe963a63b2522e70b80a5b722ac0e6180407917403755df4de27d69cc115c683a99face8c823cbccf73c7f0d546f1300b9ee2e96aea85542527f33b649f1885caebe19cf75d9a645807f03565c65bd4c99c8f6bb000644cfb56969eac3e9331c254b08aa279ceb64c47ef66be3f071e28b3a5a21e48cdfc3335d8b52e80a09a104a791ace6a2c1b4da88c52f9cc28c54a324e126ec91a988c1fe4e21afc8a84d0e876e01502386f74e7fc24fc32aa249075dd222361aea119d4824db2a797d58886e93bdd60556e504bb190b76a451a4e7b0431973c0410e71e808d0962415503931bbde3dfce5186b371c5bf729861f239ef626b7217d071dfd62bac877a847f2ac2dca07597a0bb9dc1969bed40606c025c4ff7b53a4a6bd921642199c16ede8165ed28da161739fa8d33f9f483212759498c1219d246092d14c9ae63808f58f03c8ca746904ba51fa326d793cea80cda411c85d35894bdb5",
  },
  {
    satotxApiPrefix: "https://satotx.volt.id",
    satotxPubKey:
      "3a62ce90c189ae322150cfc68cd00739cd681babf46a9b27793413ad780ea7c4ef22afd0042bc3711588587c2b8a953ced78496cb95579b1272b8979183ea3c66d204c8eeffebfa115c596c0c561f3569fe6d6e8e06d7e82192a24a84b739838ac846db8594a565679d617695f184eb85a3902a036eb8e82f95b83acc207f0deeac87291539865765899d97cfe41169c555480372195729269ae30b6c39324a6731d6f4e46da5ba1789c6e9bd14b16426d35fd4449eecd177e2834e87fb65d9d469176ffe0c12097fcc7e2393dbaa504631487a3ad725235b4d25fe3d09c2460f8a6c0bf4defc1ffe65d5fa28e85fae11eace2a66e48a0ae2ed6bcfb4bb94296717a4a5b1b3fa9b0fb3c165e517b9b69fa8aaca7fdc7351a0ac14d110258f442f423a780bebd87ac10173ca00ee4e9f56ced0510e7f53ed41411b91286f288438c361d2a15868d1c84d6a73510ef23eee9312ae2a7162c1fcd5438788236c0571ee822c326ebd123b8a6636e7b192db2911725a20da027bfaa79c33f58174285",
  },
  {
    satotxApiPrefix: "https://satotx.metasv.com",
    satotxPubKey:
      "19d9193ee2e95d09445d28408e8a3da730b2d557cd8d39a7ae4ebbfbceb17ed5d745623529ad33d043511f3e205c1f92b6322833424d19823c3b611b3adabb74e1006e0e93a8f1e0b97ab801c6060a4c060f775998d9f003568ab4ea7633a0395eb761c36106e229394f2c271b8522a44a5ae759254f5d22927923ba85b3729460ecccca07a5556299aa7f2518814c74a2a4d48b48013d609002631f2d93c906d07077ef58d473e3d971362d1129c1ab9b8f9b1365519f0c023c1cadad5ab57240d19e256e08022fd0708951ff90a8af0655aff806c6382d0a72c13f1e52b88222d7dfc6357179b06ffcf937f9da3b0419908aa589a731e26bbaba2fa0b754bf722e338c5627b11dc24aadc4d83c35851c034936cf0df18167e856a5f0a7121d23cd48b3f8a420869a37bd1362905d7f76ff18a991f75a0f9d1bcfc18416d76691cc357cbdcc8cc0df9dbd9318a40e08adb2fb4e78b3c47bdf07eeed4f3f4e0f7e81e37460a09b857e0194c72ec03bb564b5b409d8a1b84c153186ecbb4cfdfd",
  },
  {
    satotxApiPrefix: "https://satotx.tswap.io",
    satotxPubKey:
      "a36531727b324b34baef257d223b8ba97bac06d6b631cccb271101f20ef1de2523a0a3a5367d89d98ff354fe1a07bcfb00425ab252950ce10a90dc9040930cf86a3081f0c68ea05bfd40aab3e8bfaaaf6b5a1e7a2b202892dc9b1c0fe478210799759b31ee04e842106a58d901eb5bc538c1b58b7eb774a382e7ae0d6ed706bb0b12b9b891828da5266dd9f0b381b05ecbce99fcde628360d281800cf8ccf4630b2a0a1a25cf4d103199888984cf61edaa0dad578b80dbce25b3316985a8f846ada9bf9bdb8c930e2a43e69994a9b15ea33fe6ee29fa1a6f251f8d79a5de9f1f24152efddedc01b63e2f2468005ecce7da382a64d7936b22a7cac697e1b0a48419101a802d3be554a9b582a80e5c5d8b998e5eb9684c7aaf09ef286d3d990c71be6e3f3340fdaeb2dac70a0be928b6de6ef79f353c868def3385bccd36aa871eb7c8047d3f10b0a38135cdb3577eaafa512111a7af088e8f77821a27b195c95bf80da3c59fda5ff3dd1d40f60d61c099a608b58b6de4a76146cf7b89444c1055",
  },
];
ContractUtil.init();
function checkParamSigners(signers) {
  if (signers.length != 5) {
    throw new Error("only support 5 signers");
  }
  let signer = signers[0];
  if (
    Utils.isNull(signer.satotxApiPrefix) ||
    Utils.isNull(signer.satotxPubKey)
  ) {
    throw new Error(
      `SignerFormatError-valid format example :
    signers:[{
      satotxApiPrefix: "https://api.satotx.com",
      satotxPubKey:
      "25108ec89eb96b99314619eb5b124f11f00307a833cda48f5ab1865a04d4cfa567095ea4dd47cdf5c7568cd8efa77805197a67943fe965b0a558216011c374aa06a7527b20b0ce9471e399fa752e8c8b72a12527768a9fc7092f1a7057c1a1514b59df4d154df0d5994ff3b386a04d819474efbd99fb10681db58b1bd857f6d5",
    },...]`
    );
  }
}

function parseSensibleID(sensibleID: string) {
  let sensibleIDBuf = Buffer.from(sensibleID, "hex");
  let genesisTxId = sensibleIDBuf.slice(0, 32).reverse().toString("hex");
  let genesisOutputIndex = sensibleIDBuf.readUIntLE(32, 4);
  return {
    genesisTxId,
    genesisOutputIndex,
  };
}

export class NftSigner {
  public signers: SatotxSigner[];
  public signerSelecteds: number[] = [];

  rabinPubKeyArray: Int[];
  rabinPubKeyHashArray: Bytes;
  rabinPubKeyHashArrayHash: Buffer;
  transferCheckCodeHashArray: Bytes[];
  unlockContractCodeHashArray: Bytes[];

  constructor({
    signerConfigs = defaultSignerConfigs,
    signerSelecteds,
  }: {
    signerConfigs?: SignerConfig[];
    signerSelecteds?: number[];
  }) {
    checkParamSigners(signerConfigs);
    this.signers = signerConfigs.map(
      (v) => new SatotxSigner(v.satotxApiPrefix, v.satotxPubKey)
    );

    if (signerSelecteds) {
      if (signerSelecteds.length < nftProto.SIGNER_VERIFY_NUM) {
        throw new Error(
          `the length of signerSeleteds should not less than ${nftProto.SIGNER_VERIFY_NUM}`
        );
      }
      this.signerSelecteds = signerSelecteds;
    } else {
      for (let i = 0; i < nftProto.SIGNER_VERIFY_NUM; i++) {
        this.signerSelecteds.push(i);
      }
    }
    this.signerSelecteds.sort((a, b) => a - b);

    let rabinPubKeys = this.signers.map((v) => v.satotxPubKey);
    let rabinPubKeyHashArray = Utils.getRabinPubKeyHashArray(rabinPubKeys);
    this.rabinPubKeyHashArrayHash =
      bsv.crypto.Hash.sha256ripemd160(rabinPubKeyHashArray);
    this.rabinPubKeyHashArray = new Bytes(toHex(rabinPubKeyHashArray));
    this.rabinPubKeyArray = rabinPubKeys.map((v) => new Int(v.toString(10)));
    this.unlockContractCodeHashArray = ContractUtil.unlockContractCodeHashArray;
  }
}

export async function getNftInput(
  provider: Provider,
  {
    codehash,
    genesis,
    nftUtxo,
  }: { codehash: string; genesis: string; nftUtxo: ParamNftUtxo }
) {
  let nftInput: NftInput = {
    txId: nftUtxo.txId,
    outputIndex: nftUtxo.outputIndex,
    nftAddress: new bsv.Address(nftUtxo.tokenAddress, provider.network),
    codehash,
    genesis,
  };

  let txHex = await provider.getRawTx(nftInput.txId);
  const tx = new bsv.Transaction(txHex);
  let tokenScript = tx.outputs[nftInput.outputIndex].script;

  let curDataPartObj = nftProto.parseDataPart(tokenScript.toBuffer());
  let input = tx.inputs.find((input) => {
    let script = new bsv.Script(input.script);
    if (script.chunks.length > 0) {
      const lockingScriptBuf = Utils.getLockingScriptFromPreimage(
        script.chunks[0].buf
      );
      if (lockingScriptBuf) {
        if (nftProto.getQueryGenesis(lockingScriptBuf) == genesis) {
          return true;
        }

        let dataPartObj = nftProto.parseDataPart(lockingScriptBuf);
        dataPartObj.sensibleID = curDataPartObj.sensibleID;
        dataPartObj.tokenIndex = BN.Zero;
        const newScriptBuf = nftProto.updateScript(
          lockingScriptBuf,
          dataPartObj
        );

        let genesisHash = toHex(bsv.crypto.Hash.sha256ripemd160(newScriptBuf));

        if (genesisHash == curDataPartObj.genesisHash) {
          return true;
        }
      }
    }
  });
  if (!input) throw new Error("invalid nftUtxo");
  let preTxId = input.prevTxId.toString("hex");
  let preOutputIndex = input.outputIndex;
  let preTxHex = await provider.getRawTx(preTxId);
  const preTx = new bsv.Transaction(preTxHex);

  nftInput.satotxInfo = {
    txId: nftInput.txId,
    outputIndex: nftInput.outputIndex,
    txHex,
    preTxId,
    preOutputIndex,
    preTxHex,
  };

  nftInput.preLockingScript = preTx.outputs[preOutputIndex].script;
  nftInput.lockingScript = tx.outputs[nftInput.outputIndex].script;
  nftInput.satoshis = tx.outputs[nftInput.outputIndex].satoshis;
  nftInput.preNftAddress = bsv.Address.fromPublicKeyHash(
    Buffer.from(
      nftProto.getNftAddress(preTx.outputs[preOutputIndex].script.toBuffer()),
      "hex"
    ),
    provider.network
  );
  nftInput.nftID = nftProto
    .getNftID(nftInput.lockingScript.toBuffer())
    .toString("hex");
  nftInput.tokenIndex = nftUtxo.tokenIndex;
  nftInput.rabinPubKeyHashArrayHash = nftProto.getRabinPubKeyHashArrayHash(
    nftInput.lockingScript.toBuffer()
  );

  return nftInput;
}

export async function getNftGenesisInput(
  provider: Provider,
  {
    codehash,
    genesis,
    sensibleId,
  }: {
    codehash: string;
    genesis: string;
    sensibleId: string;
  }
) {
  let { genesisTxId, genesisOutputIndex } = parseSensibleID(sensibleId);

  let genesisInput: NftGenesisInput;
  let unspent: NftInput;
  let firstGenesisTxHex = await provider.getRawTx(genesisTxId);
  let firstGenesisTx = new bsv.Transaction(firstGenesisTxHex);

  let contractScript = firstGenesisTx.outputs[genesisOutputIndex].script;
  let issueCodehash: string;
  let genesisPublicKey: string;
  for (let i = 0; i < contractScript.chunks.length; i++) {
    let chunk = contractScript.chunks[i];
    if (!genesisPublicKey && chunk.buf && toHex(chunk.buf).length == 66)
      genesisPublicKey = toHex(chunk.buf);
    if (chunk.opcodenum == bsv.Opcode.OP_RETURN) {
      let newScript = new bsv.Script();
      newScript.chunks = contractScript.chunks.slice(0, i + 1);
      issueCodehash = toHex(
        bsv.crypto.Hash.sha256ripemd160(newScript.toBuffer())
      );
      break;
    }
  }
  let scriptBuffer = contractScript.toBuffer();

  let spent = await provider.getIsUtxoSpent(genesisTxId, genesisOutputIndex);
  if (!spent) {
    genesisInput = {
      txId: genesisTxId,
      outputIndex: genesisOutputIndex,
    };
  } else {
    if (!unspent) {
      let _dataPartObj = nftProto.parseDataPart(scriptBuffer);
      _dataPartObj.sensibleID = {
        txid: genesisTxId,
        index: genesisOutputIndex,
      };
      let newScriptBuf = nftProto.updateScript(scriptBuffer, _dataPartObj);
      let issueGenesis = nftProto.getQueryGenesis(newScriptBuf);
      let issueUtxos = await provider.getNftUtxos(
        issueCodehash,
        issueGenesis,
        getZeroAddress(provider.network).toString()
      );
      if (issueUtxos.length > 0) {
        unspent = issueUtxos[0];
      }
    }

    if (unspent) {
      genesisInput = {
        txId: unspent.txId,
        outputIndex: unspent.outputIndex,
      };
    }
  }

  if (!genesisInput) {
    throw new Error("token supply is fixed");
  }
  let txHex = await provider.getRawTx(genesisInput.txId);
  const tx = new bsv.Transaction(txHex);
  let preTxId = tx.inputs[0].prevTxId.toString("hex");
  let preOutputIndex = tx.inputs[0].outputIndex;
  let preTxHex = await provider.getRawTx(preTxId);
  genesisInput.satotxInfo = {
    txId: genesisInput.txId,
    outputIndex: genesisInput.outputIndex,
    txHex,
    preTxId,
    preOutputIndex,
    preTxHex,
  };

  let output = tx.outputs[genesisInput.outputIndex];
  genesisInput.satoshis = output.satoshis;
  genesisInput.lockingScript = output.script;

  genesisInput.nftCodehash = codehash;
  genesisInput.nftGenesis = genesis;
  genesisInput.sensibleID = {
    txid: genesisTxId,
    index: genesisOutputIndex,
  };
  genesisInput.publicKey = genesisPublicKey;

  genesisInput.totalSupply = nftProto.getTotalSupply(output.script.toBuffer());

  genesisInput.rabinPubKeyHashArrayHash = nftProto.getRabinPubKeyHashArrayHash(
    output.script.toBuffer()
  );

  let genesisContract = NftGenesisFactory.createContract(
    new bsv.PublicKey(genesisPublicKey)
  );
  genesisContract.setFormatedDataPartFromLockingScript(
    genesisInput.lockingScript
  );

  return { genesisInput, genesisContract };
}

export async function createNftGenesisTx({
  nftSigner,
  genesisPublicKey,
  totalSupply,
  opreturnData,
  utxos,
  changeAddress,
}: {
  nftSigner: NftSigner;
  genesisPublicKey: string;
  totalSupply: string;
  opreturnData?: any;
  utxos: ParamUtxo[];
  changeAddress?: string;
}): Promise<{
  txComposer: TxComposer;
  genesisContract: NftGenesis;
}> {
  let estimateSatoshis = await createNftGenesisTx.estimateFee({
    opreturnData,
    utxoMaxCount: utxos.length,
  });
  let balance = utxos.reduce((pre, cur) => cur.satoshis + pre, 0);
  if (balance < estimateSatoshis) {
    throw new Error(
      `Insufficient balance.It take more than ${estimateSatoshis}, but only ${balance}.`
    );
  }

  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  let genesisContract = NftGenesisFactory.createContract(
    new bsv.PublicKey(genesisPublicKey)
  );
  genesisContract.setFormatedDataPart({
    totalSupply: new BN(totalSupply.toString()),
    rabinPubKeyHashArrayHash: toHex(nftSigner.rabinPubKeyHashArrayHash),
  });

  const txComposer = new TxComposer();

  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  const genesisOutputIndex = txComposer.appendOutput({
    lockingScript: genesisContract.lockingScript,
    satoshis: txComposer.getDustThreshold(
      genesisContract.lockingScript.toBuffer().length
    ),
  });

  //If there is opReturn, add it to the second output
  if (opreturnData) {
    txComposer.appendOpReturnOutput(opreturnData);
  }

  txComposer.appendChangeOutput(changeAddress);
  txComposer.checkFeeRate();

  return { txComposer, genesisContract };
}

/**
 * Estimate the cost of genesis
 * The minimum cost required in the case of 10 utxo inputs
 * @param opreturnData
 * @param utxoMaxCount Maximum number of BSV UTXOs supported
 * @returns
 */
createNftGenesisTx.estimateFee = function ({
  opreturnData,
  utxoMaxCount = 10,
}: {
  opreturnData?: any;
  utxoMaxCount?: number;
}) {
  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOutput(NftGenesisFactory.getLockingScriptSize());

  if (opreturnData) {
    stx.addOpReturnOutput(
      bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length
    );
  }
  stx.addP2PKHOutput();
  return stx.getFee();
};

export async function createNftMetaDataTx({
  utxos,
  metaData,
  changeAddress,
}: {
  utxos: ParamUtxo[];
  metaData: NftMetaData;
  changeAddress?: string;
}): Promise<{
  txComposer: TxComposer;
}> {
  let opreturnData = [JSON.stringify(metaData), "sensible"];

  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  const txComposer = new TxComposer();

  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  txComposer.appendOpReturnOutput(opreturnData);

  txComposer.appendChangeOutput(changeAddress);
  txComposer.checkFeeRate();

  return { txComposer };
}

createNftMetaDataTx.estimateFee = function ({
  metaData,
  utxoMaxCount = 10,
}: {
  metaData: NftMetaData;
  utxoMaxCount?: number;
}) {
  let opreturnData = [JSON.stringify(metaData), "sensible"];

  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOpReturnOutput(
    bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length
  );
  stx.addP2PKHOutput();
  return stx.getFee();
};

export async function createNftMintTx({
  nftSigner,
  genesisInput,
  genesisContract,

  receiverAddress,

  metaTxId,
  metaOutputIndex,
  opreturnData,
  utxos,
  changeAddress,
}: {
  nftSigner: NftSigner;

  genesisInput: NftGenesisInput;
  genesisContract: NftGenesis;

  metaTxId?: string;
  metaOutputIndex?: number;
  receiverAddress: string;

  opreturnData?: any;
  utxos: ParamUtxo[];
  changeAddress?: string;
}): Promise<{
  txComposer: TxComposer;
  tokenIndex: string;
}> {
  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  let balance = utxos.reduce((pre, cur) => pre + cur.satoshis, 0);
  let estimateSatoshis = createNftMintTx.estimateFee({
    genesisInput,
    opreturnData,
    utxoMaxCount: utxos.length,
  });
  if (balance < estimateSatoshis) {
    throw new Error(
      `Insufficient balance.It take more than ${estimateSatoshis}, but only ${balance}.`
    );
  }

  let network = new bsv.Address(utxos[0].address).network.alias;

  let originDataPart = genesisContract.getFormatedDataPart();
  genesisContract.setFormatedDataPart({
    sensibleID: genesisInput.sensibleID,
    tokenIndex: BN.Zero,
  });
  let genesisHash = genesisContract.getScriptHash();
  genesisContract.setFormatedDataPart(originDataPart);

  let nftContract = NftFactory.createContract(
    nftSigner.unlockContractCodeHashArray,
    genesisInput.nftCodehash
  );
  nftContract.setFormatedDataPart({
    metaidOutpoint: {
      txid: metaTxId,
      index: metaOutputIndex,
    },
    nftAddress: toHex(new bsv.Address(receiverAddress).hashBuffer),
    totalSupply: genesisContract.getFormatedDataPart().totalSupply,
    tokenIndex: genesisContract.getFormatedDataPart().tokenIndex,
    genesisHash,
    rabinPubKeyHashArrayHash:
      genesisContract.getFormatedDataPart().rabinPubKeyHashArrayHash,
    sensibleID: genesisInput.sensibleID,
  });

  if (
    originDataPart.rabinPubKeyHashArrayHash !=
    toHex(nftSigner.rabinPubKeyHashArrayHash)
  ) {
    throw new Error("Invalid signers.");
  }

  let { rabinData, rabinPubKeyIndexArray, rabinPubKeyVerifyArray } =
    await getRabinData(
      nftSigner.signers,
      nftSigner.signerSelecteds,
      genesisContract.isFirstGenesis() ? null : genesisInput.satotxInfo
    );

  const txComposer = new TxComposer();

  //The first input is the genesis contract
  const genesisInputIndex = txComposer.appendInput(genesisInput);
  txComposer.addInputInfo({
    inputIndex: genesisInputIndex,
    address: new bsv.PublicKey(genesisInput.publicKey)
      .toAddress(network)
      .toString(),
    sighashType,
  });

  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  let genesisContractSatoshis = 0;
  const genesisDataPartObj = genesisContract.getFormatedDataPart();
  if (
    genesisDataPartObj.tokenIndex.lt(genesisDataPartObj.totalSupply.sub(BN.One))
  ) {
    genesisDataPartObj.tokenIndex = genesisDataPartObj.tokenIndex.add(BN.One);
    genesisDataPartObj.sensibleID =
      nftContract.getFormatedDataPart().sensibleID;
    let nextGenesisContract = genesisContract.clone();
    nextGenesisContract.setFormatedDataPart(genesisDataPartObj);
    genesisContractSatoshis = txComposer.getDustThreshold(
      nextGenesisContract.lockingScript.toBuffer().length
    );
    txComposer.appendOutput({
      lockingScript: nextGenesisContract.lockingScript,
      satoshis: genesisContractSatoshis,
    });
  }

  //The following output is the NFT
  const nftOutputIndex = txComposer.appendOutput({
    lockingScript: nftContract.lockingScript,
    satoshis: txComposer.getDustThreshold(
      nftContract.lockingScript.toBuffer().length
    ),
  });

  //If there is opReturn, add it to the output
  let opreturnScriptHex = "";
  if (opreturnData) {
    const opreturnOutputIndex = txComposer.appendOpReturnOutput(opreturnData);
    opreturnScriptHex = txComposer
      .getOutput(opreturnOutputIndex)
      .script.toHex();
  }

  for (let c = 0; c < 2; c++) {
    txComposer.clearChangeOutput();
    const changeOutputIndex = txComposer.appendChangeOutput(changeAddress);
    let unlockResult = genesisContract.unlock({
      txPreimage: new SigHashPreimage(
        txComposer.getPreimage(genesisInputIndex)
      ),
      sig: new Sig(PLACE_HOLDER_SIG),
      rabinMsg: rabinData.rabinMsg,
      rabinPaddingArray: rabinData.rabinPaddingArray,
      rabinSigArray: rabinData.rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray: nftSigner.rabinPubKeyHashArray,
      genesisSatoshis: genesisContractSatoshis,
      nftScript: new Bytes(txComposer.getOutput(nftOutputIndex).script.toHex()),
      nftSatoshis: txComposer.getOutput(nftOutputIndex).satoshis,
      changeAddress: new Ripemd160(
        toHex(new bsv.Address(changeAddress).hashBuffer)
      ),
      changeSatoshis:
        changeOutputIndex != -1
          ? txComposer.getOutput(changeOutputIndex).satoshis
          : 0,
      opReturnScript: new Bytes(opreturnScriptHex),
    });

    txComposer
      .getInput(genesisInputIndex)
      .setScript(unlockResult.toScript() as bsv.Script);
  }

  txComposer.checkFeeRate();

  let tokenIndex = nftContract.getFormatedDataPart().tokenIndex.toString(10);

  return {
    txComposer,
    tokenIndex,
  };
}

/**
 * Estimate the fee of createNftMintTx
 * The minimum cost required in the case of 10 utxo inputs .
 * @param genesisInput
 * @param opreturnData
 * @param utxoMaxCount Maximum number of BSV UTXOs supported
 * @returns
 */
createNftMintTx.estimateFee = function ({
  genesisInput,
  opreturnData,
  utxoMaxCount = 10,
}: {
  genesisInput: NftGenesisInput;
  opreturnData?: any;
  utxoMaxCount?: number;
}) {
  let p2pkhInputNum = utxoMaxCount;

  let stx = new SizeTransaction();
  stx.addInput(
    NftGenesisFactory.calUnlockingScriptSize(opreturnData),
    genesisInput.satoshis
  );
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOutput(NftGenesisFactory.getLockingScriptSize());

  stx.addOutput(NftFactory.getLockingScriptSize());
  if (opreturnData) {
    stx.addOpReturnOutput(
      bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length
    );
  }
  stx.addP2PKHOutput();

  return stx.getFee();
};

export async function createNftTransferTx({
  nftSigner,
  nftInput,
  receiverAddress,
  opreturnData,
  utxos,
  changeAddress,
}: {
  nftSigner: NftSigner;
  nftInput: NftInput;
  receiverAddress: string;
  opreturnData?: any;
  utxos: ParamUtxo[];
  changeAddress?: string;
}): Promise<{ txComposer: TxComposer }> {
  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  let balance = utxos.reduce((pre, cur) => pre + cur.satoshis, 0);
  let estimateSatoshis = createNftTransferTx.estimateFee({
    nftInput,
    opreturnData,
    utxoMaxCount: utxos.length,
  });
  if (balance < estimateSatoshis) {
    throw new Error(
      `Insufficient balance.It take more than ${estimateSatoshis}, but only ${balance}.`
    );
  }

  //validate signers
  const nftScriptBuf = nftInput.lockingScript.toBuffer();
  let dataPartObj = nftProto.parseDataPart(nftScriptBuf);
  dataPartObj.nftAddress = toHex(new bsv.Address(receiverAddress).hashBuffer);
  const lockingScriptBuf = nftProto.updateScript(nftScriptBuf, dataPartObj);
  if (
    dataPartObj.rabinPubKeyHashArrayHash !=
    toHex(nftSigner.rabinPubKeyHashArrayHash)
  ) {
    throw new Error("Invalid signers.");
  }

  let { rabinDatas, rabinPubKeyIndexArray, rabinPubKeyVerifyArray } =
    await getRabinDatas(nftSigner.signers, nftSigner.signerSelecteds, [
      nftInput.satotxInfo,
    ]);

  const txComposer = new TxComposer();

  let prevouts = new Prevouts();

  // token contract input
  const nftInputIndex = txComposer.appendInput(nftInput);
  prevouts.addVout(nftInput.txId, nftInput.outputIndex);
  txComposer.addInputInfo({
    inputIndex: nftInputIndex,
    address: nftInput.nftAddress.toString(),
    sighashType,
  });

  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    prevouts.addVout(utxo.txId, utxo.outputIndex);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  //tx addOutput nft
  const nftOutputIndex = txComposer.appendOutput({
    lockingScript: bsv.Script.fromBuffer(lockingScriptBuf),
    satoshis: txComposer.getDustThreshold(lockingScriptBuf.length),
  });

  //tx addOutput OpReturn
  let opreturnScriptHex = "";
  if (opreturnData) {
    const opreturnOutputIndex = txComposer.appendOpReturnOutput(opreturnData);
    opreturnScriptHex = txComposer
      .getOutput(opreturnOutputIndex)
      .script.toHex();
  }

  //The first round of calculations get the exact size of the final transaction, and then change again
  //Due to the change, the script needs to be unlocked again in the second round
  //let the fee to be exact in the second round

  for (let c = 0; c < 2; c++) {
    txComposer.clearChangeOutput();
    const changeOutputIndex = txComposer.appendChangeOutput(changeAddress);

    const nftContract = NftFactory.createContract(
      nftSigner.unlockContractCodeHashArray,
      nftInput.codehash
    );
    let dataPartObj = nftProto.parseDataPart(nftInput.lockingScript.toBuffer());
    nftContract.setFormatedDataPart(dataPartObj);
    const unlockingContract = nftContract.unlock({
      txPreimage: new SigHashPreimage(txComposer.getPreimage(nftInputIndex)),
      prevouts: new Bytes(prevouts.toHex()),
      rabinMsg: rabinDatas[0].rabinMsg,
      rabinPaddingArray: rabinDatas[0].rabinPaddingArray,
      rabinSigArray: rabinDatas[0].rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray: nftSigner.rabinPubKeyHashArray,
      prevNftAddress: new Bytes(toHex(nftInput.preNftAddress.hashBuffer)),
      genesisScript: nftInput.preNftAddress.hashBuffer.equals(
        Buffer.alloc(20, 0)
      )
        ? new Bytes(nftInput.preLockingScript.toHex())
        : new Bytes(""),
      senderPubKey: new PubKey(
        nftInput.publicKey
          ? toHex(nftInput.publicKey.toBuffer())
          : PLACE_HOLDER_PUBKEY
      ),
      senderSig: new Sig(PLACE_HOLDER_SIG),
      receiverAddress: new Bytes(
        toHex(new bsv.Address(receiverAddress).hashBuffer)
      ),
      nftOutputSatoshis: new Int(txComposer.getOutput(nftOutputIndex).satoshis),
      opReturnScript: new Bytes(opreturnScriptHex),
      changeAddress: new Ripemd160(
        toHex(new bsv.Address(changeAddress).hashBuffer)
      ),
      changeSatoshis: new Int(
        changeOutputIndex != -1
          ? txComposer.getOutput(changeOutputIndex).satoshis
          : 0
      ),
      operation: nftProto.NFT_OP_TYPE.TRANSFER,
    });

    txComposer
      .getInput(nftInputIndex)
      .setScript(unlockingContract.toScript() as bsv.Script);
  }

  txComposer.checkFeeRate();

  return { txComposer };
}

createNftTransferTx.estimateFee = function ({
  nftInput,
  opreturnData,
  utxoMaxCount = 10,
}: {
  nftInput: NftInput;
  opreturnData?: any;
  utxoMaxCount?: number;
}) {
  let genesisScript = nftInput.preNftAddress.hashBuffer.equals(
    Buffer.alloc(20, 0)
  )
    ? new Bytes(nftInput.preLockingScript.toHex())
    : new Bytes("");

  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();
  stx.addInput(
    NftFactory.calUnlockingScriptSize(
      p2pkhInputNum,
      genesisScript,
      "",
      opreturnData,
      nftProto.NFT_OP_TYPE.TRANSFER
    ),
    nftInput.satoshis
  );
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOutput(NftFactory.getLockingScriptSize());
  if (opreturnData) {
    stx.addOpReturnOutput(
      bsv.Script.buildSafeDataOut(opreturnData).toBuffer().length
    );
  }
  stx.addP2PKHOutput();

  return stx.getFee();
};

export async function createNftUnlockCheckContractTx({
  nftUnlockType,
  codehash,
  nftID,
  utxos,
  changeAddress,
}: {
  nftUnlockType: NFT_UNLOCK_CONTRACT_TYPE;
  codehash: string;
  nftID: string;
  utxos: ParamUtxo[];
  changeAddress?: string;
}) {
  if (!changeAddress) {
    changeAddress = utxos[0].address;
  }

  //create unlockCheck contract
  let unlockCheckContract =
    NftUnlockContractCheckFactory.createContract(nftUnlockType);
  unlockCheckContract.setFormatedDataPart({
    nftCodeHash: codehash,
    nftID: nftID,
  });

  const txComposer = new TxComposer();

  //tx addInput utxo
  const p2pkhInputIndexs = utxos.map((utxo) => {
    const inputIndex = txComposer.appendP2PKHInput(utxo);
    txComposer.addInputInfo({
      inputIndex,
      address: utxo.address.toString(),
      sighashType,
    });
    return inputIndex;
  });

  const unlockCheckOutputIndex = txComposer.appendOutput({
    lockingScript: unlockCheckContract.lockingScript,
    satoshis: txComposer.getDustThreshold(
      unlockCheckContract.lockingScript.toBuffer().length
    ),
  });

  let changeOutputIndex = txComposer.appendChangeOutput(changeAddress);

  return { txComposer, unlockCheckContract };
}

createNftUnlockCheckContractTx.estimateFee = function ({
  nftUnlockType,
  utxoMaxCount = 10,
}: {
  nftUnlockType: NFT_UNLOCK_CONTRACT_TYPE;
  utxoMaxCount?: number;
}) {
  let p2pkhInputNum = utxoMaxCount;
  let stx = new SizeTransaction();
  for (let i = 0; i < p2pkhInputNum; i++) {
    stx.addP2PKHInput();
  }

  stx.addOutput(
    NftUnlockContractCheckFactory.getLockingScriptSize(nftUnlockType)
  );
  stx.addP2PKHOutput();
  return stx.getFee();
};

/**
 * Get codehash and genesis from genesis tx.
 * @param genesisTx genesis tx
 * @param genesisOutputIndex (Optional) outputIndex - default value is 0.
 * @returns
 */
export function getNftGenesisInfo(
  nftSigner: NftSigner,
  genesisTxRawHex: string,
  genesisOutputIndex: number = 0
) {
  let genesisTx = new bsv.Transaction(genesisTxRawHex);
  //calculate genesis/codehash
  let genesis: string, codehash: string, sensibleId: string;
  let genesisTxId = genesisTx.id;
  let genesisLockingScriptBuf =
    genesisTx.outputs[genesisOutputIndex].script.toBuffer();
  const dataPartObj = nftProto.parseDataPart(genesisLockingScriptBuf);
  dataPartObj.sensibleID = {
    txid: genesisTxId,
    index: genesisOutputIndex,
  };
  genesisLockingScriptBuf = nftProto.updateScript(
    genesisLockingScriptBuf,
    dataPartObj
  );

  let tokenContract = NftFactory.createContract(
    nftSigner.unlockContractCodeHashArray
  );
  tokenContract.setFormatedDataPart({
    rabinPubKeyHashArrayHash: toHex(nftSigner.rabinPubKeyHashArrayHash),
    sensibleID: {
      txid: genesisTxId,
      index: genesisOutputIndex,
    },
    genesisHash: toHex(Utils.getScriptHashBuf(genesisLockingScriptBuf)),
  });

  let scriptBuf = tokenContract.lockingScript.toBuffer();
  genesis = nftProto.getQueryGenesis(scriptBuf);
  codehash = tokenContract.getCodeHash();
  sensibleId = toHex(Utils.getOutpointBuf(genesisTxId, genesisOutputIndex));

  return { codehash, genesis, sensibleId };
}

export async function selectNftSigners(
  signerConfigs: SignerConfig[] = defaultSignerConfigs
) {
  return await selectSigners(
    signerConfigs,
    nftProto.SIGNER_NUM,
    nftProto.SIGNER_VERIFY_NUM
  );
}
