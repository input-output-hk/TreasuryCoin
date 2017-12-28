package examples.hybrid.state

import examples.hybrid.TreasuryManager
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.{RegisterTransaction, TreasuryTransaction}
import treasury.crypto.core.PubKey

import scala.util.Try

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

case class TreasuryState(epochNum: Int,
                         committeePubKeys: Seq[PubKey],
                         expertsPubKeys: Seq[PubKey],
                         votersPubKeys: Seq[PubKey])
                         /*distrKeyGen: Seq[DKGTransaction],
                           ballots: Seq[BallotTransaction]),
                           .... */ {

  protected def apply(tx: TreasuryTransaction): Try[TreasuryState] = tx match {
      case t: RegisterTransaction => Try { t.role match {
        case Role.Committee => TreasuryState(epochNum, committeePubKeys :+ t.pubKey, expertsPubKeys, votersPubKeys)
        case Role.Expert => TreasuryState(epochNum, committeePubKeys, expertsPubKeys :+ t.pubKey, votersPubKeys)
        case Role.Voter => TreasuryState(epochNum, committeePubKeys, expertsPubKeys, votersPubKeys :+ t.pubKey)
      }}
  }

  def apply(block: HybridBlock): Try[TreasuryState] = Try {
    block match {
      case b:PosBlock => {
        val trTxs = b.transactions.collect { case t: TreasuryTransaction => t }
        trTxs.foldLeft(this) { case (state, tx) => state.apply(tx).get }
      }
      case _ => this
    }
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
}

object TreasuryState {

  def generate(history: HybridHistory): Try[TreasuryState] = Try {

    val stor = history.storage
    val currentHeight = stor.heightOf(stor.bestPosId).get.toInt

    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochLen = currentHeight - (epochNum * TreasuryManager.EPOCH_LEN)

    val epochBlocksIds = history.lastBlockIds(history.modifierById(stor.bestPosId).get, currentEpochLen)

    val initial = TreasuryState(epochNum, Seq(), Seq(), Seq())

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foldLeft(initial) { case (state, blockId) =>
      history.modifierById(blockId) match {
        case Some(b:PosBlock) => {
          val trTxs = b.transactions.collect {case t:TreasuryTransaction => t}
          trTxs.foldLeft(state) { case (state, tx) =>
            state.apply(tx).get
          }
        }
        case _ => state
      }
    }
  }
}
