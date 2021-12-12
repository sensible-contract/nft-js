import { Utxo } from "@sensible-contract/abstract-provider";
import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  ContractAdapter,
  dummyAddress,
  dummyCodehash,
  dummyPadding,
  dummyPayload,
  dummyRabinPubKey,
  dummyRabinPubKeyHashArray,
  dummySigBE,
  dummyTx,
  dummyTxId,
  Prevouts,
} from "@sensible-contract/sdk-core";
import {
  buildContractClass,
  Bytes,
  FunctionCall,
  getPreimage,
  Int,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import { TxComposer } from "@sensible-contract/tx-composer";
import { SIGNER_VERIFY_NUM } from "../contract-proto/nft.proto";
import * as unlockProto from "../contract-proto/nftUnlockContractCheck.proto";
import { NftFactory } from "./nft";
export class NftUnlockContractCheck extends ContractAdapter {
  constuctParams: { unlockType: NFT_UNLOCK_CONTRACT_TYPE };
  private _formatedDataPart: unlockProto.FormatedDataPart;
  constructor(constuctParams: { unlockType: NFT_UNLOCK_CONTRACT_TYPE }) {
    let desc;
    switch (constuctParams.unlockType) {
      case NFT_UNLOCK_CONTRACT_TYPE.OUT_3:
        desc = require("../contract-desc/nftUnlockContractCheck_desc.json");
        break;
      case NFT_UNLOCK_CONTRACT_TYPE.OUT_6:
        desc = require("../contract-desc/nftUnlockContractCheck_6_desc.json");
        break;
      case NFT_UNLOCK_CONTRACT_TYPE.OUT_10:
        desc = require("../contract-desc/nftUnlockContractCheck_10_desc.json");
        break;
      case NFT_UNLOCK_CONTRACT_TYPE.OUT_20:
        desc = require("../contract-desc/nftUnlockContractCheck_20_desc.json");
        break;
      case NFT_UNLOCK_CONTRACT_TYPE.OUT_100:
        desc = require("../contract-desc/nftUnlockContractCheck_100_desc.json");
        break;
      default:
        throw "invalid checkType";
    }
    const NftUnlockContractCheckClass = buildContractClass(desc);
    const unlockCheckContract = new NftUnlockContractCheckClass();
    super(unlockCheckContract);

    this.constuctParams = constuctParams;
  }

  clone() {
    let contract = new NftUnlockContractCheck(this.constuctParams);
    contract.setFormatedDataPart(this.getFormatedDataPart());
    return contract;
  }

  public setFormatedDataPart(dataPart: unlockProto.FormatedDataPart) {
    this._formatedDataPart = Object.assign(
      {},
      this._formatedDataPart,
      dataPart
    );
    super.setDataPart(toHex(unlockProto.newDataPart(this._formatedDataPart)));
  }

  public getFormatedDataPart() {
    return this._formatedDataPart;
  }

  public unlock({
    txPreimage,
    nftInputIndex,
    nftScript,
    prevouts,
    rabinMsg,
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    rabinPubKeyHashArray,
    nOutputs,
    nftOutputIndex,
    nftOutputAddress,
    nftOutputSatoshis,
    otherOutputArray,
  }: {
    txPreimage: SigHashPreimage;
    nftInputIndex: number;
    nftScript: Bytes;
    prevouts: Bytes;
    rabinMsg: Bytes;
    rabinPaddingArray: Bytes[];
    rabinSigArray: Int[];
    rabinPubKeyIndexArray: number[];
    rabinPubKeyVerifyArray: Int[];
    rabinPubKeyHashArray: Bytes;
    nOutputs: number;
    nftOutputIndex: number;
    nftOutputAddress: Bytes;
    nftOutputSatoshis: number;
    otherOutputArray: Bytes;
  }) {
    return this._contract.unlock(
      txPreimage,
      nftInputIndex,
      nftScript,
      prevouts,
      rabinMsg,
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray,
      nOutputs,
      nftOutputIndex,
      nftOutputAddress,
      nftOutputSatoshis,
      otherOutputArray
    ) as FunctionCall;
  }
}
export enum NFT_UNLOCK_CONTRACT_TYPE {
  OUT_3 = 1,
  OUT_6,
  OUT_10,
  OUT_20,
  OUT_100,
  UNSUPPORT,
}

let _unlockContractTypeInfos = [
  {
    type: NFT_UNLOCK_CONTRACT_TYPE.OUT_3,
    out: 3,
    lockingScriptSize: 0,
  },
  {
    type: NFT_UNLOCK_CONTRACT_TYPE.OUT_6,
    out: 6,
    lockingScriptSize: 0,
  },
  {
    type: NFT_UNLOCK_CONTRACT_TYPE.OUT_10,
    out: 10,
    lockingScriptSize: 0,
  },
  {
    type: NFT_UNLOCK_CONTRACT_TYPE.OUT_20,
    out: 20,
    lockingScriptSize: 0,
  },
  {
    type: NFT_UNLOCK_CONTRACT_TYPE.OUT_100,
    out: 100,
    lockingScriptSize: 0,
  },
];

export class NftUnlockContractCheckFactory {
  public static unlockContractTypeInfos: {
    type: NFT_UNLOCK_CONTRACT_TYPE;
    out: number;
    lockingScriptSize: number;
  }[] = _unlockContractTypeInfos;

  public static getLockingScriptSize(unlockType: NFT_UNLOCK_CONTRACT_TYPE) {
    return this.unlockContractTypeInfos.find((v) => v.type == unlockType)
      .lockingScriptSize;
  }

  public static getOptimumType(outCount: number) {
    if (outCount <= 3) {
      return NFT_UNLOCK_CONTRACT_TYPE.OUT_3;
    } else if (outCount <= 6) {
      return NFT_UNLOCK_CONTRACT_TYPE.OUT_6;
    } else if (outCount <= 10) {
      return NFT_UNLOCK_CONTRACT_TYPE.OUT_10;
    } else if (outCount <= 20) {
      return NFT_UNLOCK_CONTRACT_TYPE.OUT_20;
    } else if (outCount <= 100) {
      return NFT_UNLOCK_CONTRACT_TYPE.OUT_100;
    } else {
      return NFT_UNLOCK_CONTRACT_TYPE.UNSUPPORT;
    }
  }

  public static createContract(
    unlockType: NFT_UNLOCK_CONTRACT_TYPE
  ): NftUnlockContractCheck {
    return new NftUnlockContractCheck({ unlockType });
  }

  public static getDummyInstance(unlockType: NFT_UNLOCK_CONTRACT_TYPE) {
    let contract = this.createContract(unlockType);
    contract.setFormatedDataPart({
      nftID: dummyCodehash.toBuffer().toString("hex"),
      nftCodeHash: "0000000000000000000000000000000000000000",
    });
    return contract;
  }

  public static createDummyTx(
    unlockType: NFT_UNLOCK_CONTRACT_TYPE,
    utxoMaxCount: number = 3
  ) {
    const dummySatoshis = 100000000000000;
    const dummyUnlockScript =
      "483045022100e922b0bd9c58a4bbc9fce7799238b3bb140961bb061f6a820120bcf61746ec3c022062a926ce4cd34837c4c922bb1f6b8e971450808d078edec9260dc04594e135ea412102ed9e3017533cb75a86d471b94005c87154a2cb27f435480fdffbc5e963c46a8d";
    let contract = this.getDummyInstance(unlockType);
    const txComposer = new TxComposer();

    let utxos: Utxo[] = [];
    for (let i = 0; i < utxoMaxCount; i++) {
      utxos.push({
        txId: dummyTxId,
        outputIndex: 0,
        satoshis: dummySatoshis,
        address: dummyAddress.toString(),
      });
    }
    const p2pkhInputIndexs = utxos.map((utxo) => {
      const inputIndex = txComposer.appendP2PKHInput(utxo);
      txComposer.addInputInfo({
        inputIndex,
        address: utxo.address.toString(),
      });
      return inputIndex;
    });

    const nftForAuctionOutputIndex = txComposer.appendOutput({
      lockingScript: contract.lockingScript,
      satoshis: txComposer.getDustThreshold(
        contract.lockingScript.toBuffer().length
      ),
    });

    let changeOutputIndex = txComposer.appendChangeOutput(dummyAddress);

    utxos.forEach((v, index) => {
      txComposer.getInput(index).setScript(new bsv.Script(dummyUnlockScript));
    });

    return txComposer;
  }

  public static calLockingScriptSize(
    unlockType: NFT_UNLOCK_CONTRACT_TYPE
  ): number {
    let contract = this.getDummyInstance(unlockType);
    return (contract.lockingScript as bsv.Script).toBuffer().length;
  }

  public static calUnlockingScriptSize(
    unlockType: NFT_UNLOCK_CONTRACT_TYPE,
    inputLength: number,
    otherOutputArray: Bytes
  ): number {
    let contract = this.getDummyInstance(unlockType);
    let nftContractInstance = NftFactory.getDummyInstance();

    const preimage = getPreimage(dummyTx, contract.lockingScript.toASM(), 1);
    const rabinMsg = new Bytes(dummyPayload);
    let paddingCountBuf = Buffer.alloc(2, 0);
    paddingCountBuf.writeUInt16LE(dummyPadding.length / 2);
    const padding = Buffer.alloc(dummyPadding.length / 2, 0);
    padding.write(dummyPadding, "hex");

    const rabinPaddingArray: Bytes[] = [];
    const rabinSigArray: Int[] = [];
    const rabinPubKeyIndexArray: number[] = [];
    const rabinPubKeyArray: Int[] = [];
    let tokenAmount = Buffer.alloc(8);
    tokenAmount.writeInt32BE(100000);

    for (let i = 0; i < SIGNER_VERIFY_NUM; i++) {
      rabinPaddingArray.push(new Bytes(dummyPadding));
      rabinSigArray.push(new Int(BN.fromString(dummySigBE, 16).toString(10)));
      rabinPubKeyIndexArray.push(i);
      rabinPubKeyArray.push(new Int(dummyRabinPubKey.toString(10)));
    }

    let prevouts = new Prevouts();
    for (let i = 0; i < inputLength; i++) {
      prevouts.addVout(dummyTxId, 0);
    }

    let unlockedContract = contract.unlock({
      txPreimage: new SigHashPreimage(toHex(preimage)),
      nftInputIndex: 0,
      nftScript: new Bytes(nftContractInstance.lockingScript.toHex()),
      prevouts: new Bytes(prevouts.toHex()),
      rabinMsg: rabinMsg,
      rabinPaddingArray: rabinPaddingArray,
      rabinSigArray: rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray: rabinPubKeyArray,
      rabinPubKeyHashArray: new Bytes(toHex(dummyRabinPubKeyHashArray)),
      nOutputs: 2,
      nftOutputIndex: 0,
      nftOutputAddress: new Bytes(toHex(dummyAddress.hashBuffer)),
      nftOutputSatoshis: 1000,
      otherOutputArray,
    });
    return (unlockedContract.toScript() as bsv.Script).toBuffer().length;
  }
}
