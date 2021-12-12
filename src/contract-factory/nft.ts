import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  ContractAdapter,
  dummyAddress,
  dummyPadding,
  dummyPayload,
  dummyPk,
  dummyRabinPubKey,
  dummyRabinPubKeyHashArray,
  dummySigBE,
  dummyTx,
  dummyTxId,
  PLACE_HOLDER_SIG,
  Proto,
  Utils,
} from "@sensible-contract/sdk-core";
import {
  buildContractClass,
  Bytes,
  FunctionCall,
  getPreimage,
  Int,
  PubKey,
  Ripemd160,
  Sig,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import * as nftProto from "../contract-proto/nft.proto";
import { NFT_OP_TYPE, SIGNER_VERIFY_NUM } from "../contract-proto/nft.proto";
import { ContractUtil } from "../contractUtil";
import {
  NftUnlockContractCheckFactory,
  NFT_UNLOCK_CONTRACT_TYPE,
} from "./nftUnlockContractCheck";

enum NFT_CODE_VERSION {
  V1,
  V2,
}
export class Nft extends ContractAdapter {
  constuctParams: {
    unlockContractCodeHashArray: Bytes[];
    codeVersion: NFT_CODE_VERSION;
  };
  private _formatedDataPart: nftProto.FormatedDataPart;

  constructor(constuctParams: {
    unlockContractCodeHashArray: Bytes[];
    codeVersion: NFT_CODE_VERSION;
  }) {
    let desc =
      constuctParams.codeVersion == NFT_CODE_VERSION.V1
        ? require("../contract-desc/nft_desc.json")
        : require("../contract-desc/nft_v2_desc.json");
    let ClassObj = buildContractClass(desc);
    let contract = new ClassObj(constuctParams.unlockContractCodeHashArray);
    super(contract);

    this.constuctParams = constuctParams;
  }

  clone() {
    let contract = new Nft(this.constuctParams);
    contract.setFormatedDataPart(this.getFormatedDataPart());
    return contract;
  }

  public setFormatedDataPart(dataPart: nftProto.FormatedDataPart): void {
    this._formatedDataPart = Object.assign(
      {},
      this._formatedDataPart,
      dataPart
    );
    this._formatedDataPart.genesisFlag = nftProto.GENESIS_FLAG.FALSE;
    this._formatedDataPart.protoVersion = nftProto.PROTO_VERSION;
    this._formatedDataPart.protoType = Proto.PROTO_TYPE.NFT;
    super.setDataPart(toHex(nftProto.newDataPart(this._formatedDataPart)));
  }

  public getFormatedDataPart() {
    return this._formatedDataPart;
  }

  public unlock({
    txPreimage,
    prevouts,
    rabinMsg,
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    rabinPubKeyHashArray,
    prevNftAddress,
    genesisScript,
    senderPubKey,
    senderSig,
    receiverAddress,
    nftOutputSatoshis,
    opReturnScript,
    changeAddress,
    changeSatoshis,
    checkInputIndex,
    checkScriptTx,
    checkScriptTxOutIndex,
    lockContractInputIndex,
    lockContractTx,
    lockContractTxOutIndex,
    operation,
  }: {
    txPreimage: SigHashPreimage;
    prevouts: Bytes;
    rabinMsg: Bytes;
    rabinPaddingArray: Bytes[];
    rabinSigArray: Int[];
    rabinPubKeyIndexArray: number[];
    rabinPubKeyVerifyArray: Int[];
    rabinPubKeyHashArray: Bytes;
    prevNftAddress: Bytes;
    genesisScript?: Bytes; // only needed when use nft in the first time
    senderPubKey?: PubKey; //only transfer need
    senderSig?: Sig; // only transfer need
    receiverAddress?: Bytes; // only transfer need
    nftOutputSatoshis?: Int; // only transfer need
    opReturnScript?: Bytes; // only transfer need
    changeAddress?: Ripemd160; // only transfer need
    changeSatoshis?: Int; // only transfer need
    checkInputIndex?: number; //only unlockFromContract need
    checkScriptTx?: Bytes; //only unlockFromContract need
    checkScriptTxOutIndex?: number; //only unlockFromContract need
    lockContractInputIndex?: number; //only unlockFromContract need
    lockContractTx?: Bytes; //only unlockFromContract need
    lockContractTxOutIndex?: number; //only unlockFromContract need
    operation: NFT_OP_TYPE;
  }) {
    if (!genesisScript) {
      genesisScript = new Bytes("");
    }

    if (operation != NFT_OP_TYPE.TRANSFER) {
      senderPubKey = new PubKey("00");
      senderSig = new Sig("00");
      receiverAddress = new Bytes("");
      nftOutputSatoshis = new Int(0);
      opReturnScript = new Bytes("");
      changeAddress = new Ripemd160("00");
      changeSatoshis = new Int(0);
    }

    if (operation != NFT_OP_TYPE.UNLOCK_FROM_CONTRACT) {
      checkInputIndex = 0;
      checkScriptTx = new Bytes("");
      checkScriptTxOutIndex = 0;
      lockContractInputIndex = 0;
      lockContractTx = new Bytes("");
      lockContractTxOutIndex = 0;
    }

    if (this.constuctParams.codeVersion == NFT_CODE_VERSION.V1) {
      return this._contract.unlock(
        txPreimage,
        prevouts,
        rabinMsg,
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        rabinPubKeyVerifyArray,
        rabinPubKeyHashArray,
        prevNftAddress,
        genesisScript,
        senderPubKey,
        senderSig,
        receiverAddress,
        nftOutputSatoshis,
        opReturnScript,
        changeAddress,
        changeSatoshis,
        checkInputIndex,
        checkScriptTx,
        checkScriptTxOutIndex,
        lockContractInputIndex,
        lockContractTx,
        lockContractTxOutIndex,
        operation
      ) as FunctionCall;
    } else {
      return this._contract.unlock(
        txPreimage,
        prevouts,
        rabinMsg,
        rabinPaddingArray,
        rabinSigArray,
        rabinPubKeyIndexArray,
        rabinPubKeyVerifyArray,
        rabinPubKeyHashArray,
        prevNftAddress,
        genesisScript,
        senderPubKey,
        senderSig,
        receiverAddress,
        nftOutputSatoshis,
        opReturnScript,
        changeAddress,
        changeSatoshis,
        checkInputIndex,
        checkScriptTx,
        lockContractInputIndex,
        lockContractTx,
        operation
      ) as FunctionCall;
    }
  }
}

export class NftFactory {
  public static lockingScriptSize: number;

  public static getLockingScriptSize() {
    return this.lockingScriptSize;
  }

  public static createContractV1(unlockContractCodeHashArray: Bytes[]): Nft {
    return new Nft({
      unlockContractCodeHashArray,
      codeVersion: NFT_CODE_VERSION.V1,
    });
  }

  public static createContractV2(unlockContractCodeHashArray: Bytes[]): Nft {
    return new Nft({
      unlockContractCodeHashArray,
      codeVersion: NFT_CODE_VERSION.V2,
    });
  }

  public static createContract(
    unlockContractCodeHashArray: Bytes[],
    codehash?: string
  ): Nft {
    if (codehash == "0d0fc08db6e27dc0263b594d6b203f55fb5282e2") {
      return this.createContractV1(unlockContractCodeHashArray);
    }
    return this.createContractV2(unlockContractCodeHashArray);
  }

  public static getDummyInstance() {
    let contract = this.createContract(
      ContractUtil.unlockContractCodeHashArray
    );
    contract.setFormatedDataPart({});
    return contract;
  }

  public static calLockingScriptSize() {
    let contract = this.getDummyInstance();
    return (contract.lockingScript as bsv.Script).toBuffer().length;
  }

  public static calUnlockingScriptSize(
    bsvInputLen: number,
    genesisScript: Bytes,
    lockContractTxRawHex: string,
    opreturnData: any,
    operation: NFT_OP_TYPE
  ): number {
    let opreturnScriptHex = "";
    if (opreturnData) {
      let script = bsv.Script.buildSafeDataOut(opreturnData);
      opreturnScriptHex = script.toHex();
    }

    let contract = this.getDummyInstance();
    const preimage = getPreimage(dummyTx, contract.lockingScript.toASM(), 1);
    const sig = Buffer.from(PLACE_HOLDER_SIG, "hex");
    const rabinMsg = new Bytes(dummyPayload);
    const rabinPaddingArray: Bytes[] = [];
    const rabinSigArray: Int[] = [];
    const rabinPubKeyIndexArray: number[] = [];
    const rabinPubKeyArray: Int[] = [];
    for (let i = 0; i < SIGNER_VERIFY_NUM; i++) {
      rabinPaddingArray.push(new Bytes(dummyPadding));
      rabinSigArray.push(new Int(BN.fromString(dummySigBE, 16).toString(10)));
      rabinPubKeyIndexArray.push(i);
      rabinPubKeyArray.push(new Int(dummyRabinPubKey.toString(10)));
    }
    const nftInputIndex = 0;
    let prevouts = Buffer.alloc(0);
    const indexBuf = Utils.getUInt32Buf(0);
    const txidBuf = Utils.getTxIdBuf(dummyTxId);
    for (let i = 0; i < 1 + bsvInputLen; i++) {
      prevouts = Buffer.concat([prevouts, txidBuf, indexBuf]);
    }

    let checkScriptTx = NftUnlockContractCheckFactory.createDummyTx(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_6
    );

    let changeSatoshis = 0;
    let unlockedContract = contract.unlock({
      txPreimage: new SigHashPreimage(toHex(preimage)),
      prevouts: new Bytes(toHex(prevouts)),
      rabinMsg,
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray: rabinPubKeyArray,
      rabinPubKeyHashArray: new Bytes(toHex(dummyRabinPubKeyHashArray)),
      prevNftAddress: new Bytes(toHex(dummyAddress.hashBuffer)),
      genesisScript,
      senderPubKey: new PubKey(toHex(dummyPk)),
      senderSig: new Sig(toHex(sig)),
      receiverAddress: new Bytes(toHex(dummyAddress.hashBuffer)),
      nftOutputSatoshis: new Int(0),
      opReturnScript: new Bytes(opreturnScriptHex),
      changeAddress: new Ripemd160(toHex(dummyAddress.hashBuffer)),
      changeSatoshis: new Int(changeSatoshis),
      checkInputIndex: 0,
      checkScriptTx: new Bytes(checkScriptTx.getRawHex()),
      checkScriptTxOutIndex: 0,
      lockContractInputIndex: 0,
      lockContractTx: new Bytes(lockContractTxRawHex),
      lockContractTxOutIndex: 0,
      operation,
    });
    return (unlockedContract.toScript() as bsv.Script).toBuffer().length;
  }
}
