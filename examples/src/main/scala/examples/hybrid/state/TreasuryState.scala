package examples.hybrid.state

import examples.hybrid.TreasuryManager
import examples.hybrid.blocks.{HybridBlock, PosBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.{RegisterTTransaction, TreasuryTransaction}

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
                         registrations: Seq[RegisterTTransaction])
                         /*distrKeyGen: Seq[DKGTransaction],
                           ballots: Seq[BallotTransaction]),
                           .... */ {

  def put(tx: TreasuryTransaction): Try[TreasuryState] = Try {
    tx match {
      case t: RegisterTTransaction => TreasuryState(epochNum, registrations :+ t)
    }
  }

  def validate(mod: HybridBlock): Try[Unit] = Try {
    // TODO: add validation
    Try(Unit)
  }
}

object TreasuryState {

  def generate(history: HybridHistory): Try[TreasuryState] = Try {

    val stor = history.storage
    val currentHeight = stor.heightOf(stor.bestPosId).get.toInt

    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochLen = currentHeight - (epochNum * TreasuryManager.EPOCH_LEN)

    val epochBlocksIds = history.lastBlockIds(history.modifierById(stor.bestPosId).get, currentEpochLen)

    val initial = TreasuryState(epochNum, Seq())

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foldLeft(initial) { case (state, blockId) =>
      history.modifierById(blockId) match {
        case Some(b:PosBlock) => {
          val trTxs = b.transactions.collect {case t:TreasuryTransaction => t}
          trTxs.foldLeft(state) { case (state, tx) =>
            state.put(tx).get
          }
        }
        case _ => state
      }
    }
  }
}
