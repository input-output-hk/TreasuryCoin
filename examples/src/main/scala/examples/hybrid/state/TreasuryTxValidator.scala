package examples.hybrid.state

import examples.hybrid.TreasuryManager
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.{CommitteeRegisterTx, RegisterTTransaction, TreasuryTransaction}

class TreasuryTxValidator(val trState: TreasuryState, val height: Long) {

  @throws
  def validate(tx: TreasuryTransaction): Unit = {
    tx match {
      case t:RegisterTTransaction => validate(t)
    }
  }

  @throws
  def validate(tx: RegisterTTransaction): Unit = {
    val epochHeight = height - (trState.epochNum * TreasuryManager.EPOCH_LEN)
    require(epochHeight >= 0 && epochHeight < TreasuryManager.EPOCH_LEN, "Totally wrong situation. Probably treasury state is corrupted or problems with validation pipeline.")

    require(TreasuryManager.REGISTER_STAGE._1 <= height &&
            TreasuryManager.REGISTER_STAGE._2 > height, "Wrong height for register transaction")

    tx match {
      case t:CommitteeRegisterTx => require(trState.committeePubKeys.find(_.equals(t.committeePubKey)).isEmpty, "Committee pubkey has been already registered")
    }

    // TODO: check that transaction makes a necessary deposit. Probably there should be some special type of time-locked box.
    // tx.to.foreach()
  }

  //def validate(tx: BallotTTransaction)
}
