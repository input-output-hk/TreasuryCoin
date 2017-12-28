package examples.hybrid.state

import examples.commons.SimpleBoxTransaction
import examples.hybrid.TreasuryManager
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.{RegisterTransaction, TreasuryTransaction}

import scala.util.{Success, Try}

class TreasuryTxValidator(val trState: TreasuryState, val height: Long) {

  def validate(tx: SimpleBoxTransaction): Try[Unit] = tx match {
      case t: RegisterTransaction => validate(t)
      case _ => Success(Unit)
  }

  def validate(tx: RegisterTransaction): Try[Unit] = Try {
    val epochHeight = height - (trState.epochNum * TreasuryManager.EPOCH_LEN)
    require(epochHeight >= 0 && epochHeight < TreasuryManager.EPOCH_LEN, "Totally wrong situation. Probably treasury state is corrupted or problems with validation pipeline.")

    require(TreasuryManager.REGISTER_STAGE._1 <= height &&
            TreasuryManager.REGISTER_STAGE._2 > height, "Wrong height for register transaction")

    tx.role match {
      case Role.Committee => require(!trState.getCommitteePubKeys.contains(tx.pubKey), "Committee pubkey has been already registered")
      case Role.Expert => require(!trState.getExpertsPubKeys.contains(tx.pubKey), "Expert pubkey has been already registered")
      case Role.Voter => require(!trState.getVotersPubKeys.contains(tx.pubKey), "Voter pubkey has been already registered")
    }

    // TODO: check that transaction makes a necessary deposit. Probably there should be some special type of time-locked box.
    // tx.to.foreach()
  }

  //def validate(tx: BallotTTransaction)
}
