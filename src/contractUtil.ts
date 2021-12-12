import { Bytes } from "scryptlib";
import { NftFactory } from "./contract-factory/nft";
import { NftGenesisFactory } from "./contract-factory/nftGenesis";
import {
  NftUnlockContractCheckFactory,
  NFT_UNLOCK_CONTRACT_TYPE,
} from "./contract-factory/nftUnlockContractCheck";

function getNftUnlockContractCheckCodeHashArray(): string[] {
  let contractArray = [
    NftUnlockContractCheckFactory.createContract(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_3
    ),
    NftUnlockContractCheckFactory.createContract(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_6
    ),
    NftUnlockContractCheckFactory.createContract(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_10
    ),
    NftUnlockContractCheckFactory.createContract(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_20
    ),
    NftUnlockContractCheckFactory.createContract(
      NFT_UNLOCK_CONTRACT_TYPE.OUT_100
    ),
  ];
  return contractArray.map((v) => v.getCodeHash());
}

type ContractConfig = {
  unlockContractCodeHashArray: string[];
  tokenGenesisSize: number;
  tokenSize: number;
  unlockContractSizes: number[];
};

const dumpedConfig = {
  unlockContractCodeHashArray: [
    "5b642b4c69c444aa91d5e3467afa63b2bdc5b274",
    "531824e7e38a8b652d36f0b2e62553a5488abdec",
    "cc01ef78462606e96153505a88f2dd3e0011b8ea",
    "28f28afd78612500aa17e427fe5d03351516a3db",
    "a35e184a57d736fdcdb36ea27fe9cdd2240ad1d9",
  ],
  tokenGenesisSize: 3464,
  tokenSize: 5868,
  unlockContractSizes: [3343, 4675, 6451, 10898, 46578],
};

export class ContractUtil {
  static unlockContractCodeHashArray: Bytes[];
  static tokenCodeHash: string;
  public static init(config: ContractConfig = dumpedConfig) {
    //debug
    //config = this.dumpConfig();

    this.unlockContractCodeHashArray = config.unlockContractCodeHashArray.map(
      (v) => new Bytes(v)
    );
    NftGenesisFactory.lockingScriptSize = config.tokenGenesisSize;
    NftFactory.lockingScriptSize = config.tokenSize;
    NftUnlockContractCheckFactory.unlockContractTypeInfos.forEach((v, idx) => {
      v.lockingScriptSize = config.unlockContractSizes[idx];
    });

    let tokenContract = NftFactory.getDummyInstance();
    this.tokenCodeHash = tokenContract.getCodeHash();
  }

  static dumpConfig() {
    let config: ContractConfig = {
      unlockContractCodeHashArray: [],
      tokenGenesisSize: 0,
      tokenSize: 0,
      unlockContractSizes: [],
    };
    config.unlockContractCodeHashArray =
      getNftUnlockContractCheckCodeHashArray();
    this.unlockContractCodeHashArray = config.unlockContractCodeHashArray.map(
      (v) => new Bytes(v)
    );
    config.tokenGenesisSize = NftGenesisFactory.calLockingScriptSize();
    NftGenesisFactory.lockingScriptSize = config.tokenGenesisSize;

    config.tokenSize = NftFactory.calLockingScriptSize();
    NftFactory.lockingScriptSize = config.tokenSize;

    config.unlockContractSizes =
      NftUnlockContractCheckFactory.unlockContractTypeInfos.map((v) =>
        NftUnlockContractCheckFactory.calLockingScriptSize(v.type)
      );
    NftUnlockContractCheckFactory.unlockContractTypeInfos.forEach((v, idx) => {
      v.lockingScriptSize = config.unlockContractSizes[idx];
    });

    console.log(JSON.stringify(config));
  }
}
