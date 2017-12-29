package examples.hybrid.state

import examples.hybrid.HybridNodeViewHolder.CurrentViewWithTreasuryState
import examples.hybrid.TreasuryManager
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.{ProposalTransaction, RegisterTransaction, TreasuryTransaction}
import scorex.core.{ModifierId, VersionTag}
import treasury.crypto.core.PubKey

import scala.util.{Success, Try}

/**
  * Holds the current state of the treasury epoch
  * The idea is the following:
  * - TreasuryState will hold all treasury transactions (or extracted info from txs like committee keys, ballots, etc. - TBD) for the current epoch.
  * - Each new block should be validated against TreasuryState.
  * - Each new block should be applied to TreasuryState modifying it with new treasury transactions.
  * - TreasuryState doesn't have persistent storage. Everything will be kept in memory (at least for the initial implementation)
  * - TreasuryState should be generated/regenerated from the current History when it is needed (for instance, when node is
  * just started or block is rolled back, or new epoch begun)
  */

case class TreasuryState(epochNum: Int) {

  private var version: VersionTag = VersionTag @@ (ModifierId @@ Array.fill(32)(0: Byte))
  private var committeePubKeys: List[PubKey] = List()
  private var expertsPubKeys: List[PubKey] = List()
  private var votersPubKeys: List[PubKey] = List()

  def getCommitteePubKeys = committeePubKeys
  def getExpertsPubKeys = expertsPubKeys
  def getVotersPubKeys = votersPubKeys


  protected def apply(tx: TreasuryTransaction): Try[Unit] = tx match {
      case t: RegisterTransaction => Try { t.role match {
        case Role.Committee => committeePubKeys = committeePubKeys :+ t.pubKey
        case Role.Expert => expertsPubKeys = expertsPubKeys :+ t.pubKey
        case Role.Voter => votersPubKeys = votersPubKeys :+ t.pubKey
      }}
      case t: ProposalTransaction => Try {
        // TODO: implement state update
      }
  }

  def apply(block: HybridBlock): Try[TreasuryState] = Try {
    block match {
      case b:PosBlock => {
        val trTxs = b.transactions.collect { case t: TreasuryTransaction => t }
        trTxs.foreach(tx => apply(tx).get)
        version = VersionTag @@ block.id
      }
      case _ => this
    }
    this
  }

  def validate(block: HybridBlock, history: HybridHistory): Try[Unit] = Try {
    block match {
      case _:PowBlock => Unit
      case b:PosBlock => {
        val height = history.storage.parentHeight(b) + 1      // this block may not be applied yet so derive its height from the parent height
        val trTxs = b.transactions.collect{case t:TreasuryTransaction => t}
        val validator = new TreasuryTxValidator(this, height)
        trTxs.foreach(validator.validate(_).get)
      }
    }
  }

  def rollback(to: VersionTag): Try[TreasuryState] = Try {
    if (to sameElements version) this
    else throw new UnsupportedOperationException("Deep rollback is unsupported")
  }
}

object TreasuryState {

  def generate(history: HybridHistory): Try[TreasuryState] = Try {

    val currentHeight = history.storage.heightOf(history.storage.bestPosId).get.toInt
    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN

    val epochBlocksIds = history.lastBlockIds(history.modifierById(history.storage.bestPosId).get, currentEpochHeight)

    val state = TreasuryState(epochNum)

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => state.apply(history.modifierById(blockId).get).get)
    state
  }
}
