package examples.hybrid.state

import java.math.BigInteger

import examples.commons.Value
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction._
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import scorex.core.{ModifierId, VersionTag}
import treasury.crypto.core.PubKey
import treasury.crypto.keygen.{DecryptionManager, KeyShares}
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.voting.Tally
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.util.Try

case class Proposal(name: String, requestedSum: Value, recipient: PublicKey25519Proposition)

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

case class TreasuryState(epochNum: Int) extends ScorexLogging {

  val cs = TreasuryManager.cs

  private var version: VersionTag = VersionTag @@ (ModifierId @@ Array.fill(32)(0: Byte))
  private var committeePubKeys: List[(PublicKey25519Proposition, PubKey)] = List()
  private var expertsPubKeys: List[PublicKey25519Proposition] = List()
  private var votersPubKeys: List[PublicKey25519Proposition] = List()
  private var proposals: List[Proposal] = List()
  private var sharedPublicKey: Option[PubKey] = None
  private var votersBallots: Map[Int, Seq[VoterBallot]] = Map() // voterId -> Seq(ballot)
  private var expertsBallots: Map[Int, Seq[ExpertBallot]] = Map() // expertId -> Seq(ballot)

  private var c1SharesR1: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR1: Map[Int, KeyShares] = Map() // committeeMemberId -> KeyShares
  private var delegations: Option[Map[Int, Seq[BigInteger]]] = None  // delegations for all proposals
  private var c1SharesR2: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR2: Map[Int, KeyShares] = Map() // committeeMemberId -> KeyShares

  private var tallyResult: Map[Int, Tally.Result] = Map() // proposalId -> voting result

  def getSigningKeys(role: Role): List[PublicKey25519Proposition] = role match {
    case Role.Committee => getCommitteeSigningKeys
    case Role.Expert => getExpertsSigningKeys
    case Role.Voter => getVotersSigningKeys
  }
  def getCommitteeSigningKeys = committeePubKeys.map(_._1)
  def getCommitteeProxyKeys = committeePubKeys.map(_._2)
  def getExpertsSigningKeys = expertsPubKeys
  def getVotersSigningKeys = votersPubKeys

  def getProposals = proposals
  def getSharedPubKey = sharedPublicKey
  def getVotersBallots = votersBallots
  def getExpertsBallots = expertsBallots

  def getVoterBallotsForProposal(proposalId: Int): Seq[VoterBallot] =
    votersBallots.flatMap(ballots => ballots._2.collect { case b if b.proposalId == proposalId => b }).toSeq
  def getExpertBallotsForProposal(proposalId: Int): Seq[ExpertBallot] =
    expertsBallots.flatMap(ballots => ballots._2.collect { case b if b.proposalId == proposalId => b }).toSeq
  def getBallotsForProposal(proposalId: Int): Seq[Ballot] =
    getVoterBallotsForProposal(proposalId) ++ getExpertBallotsForProposal(proposalId)

  def getDecryptionSharesR1 = c1SharesR1
  def getKeyRecoverySharesR1 = keyRecoverySharesR1
  def getDecryptionSharesR2 = c1SharesR2
  def getKeyRecoverySharesR2 = keyRecoverySharesR2
  def getDelegations = delegations
  def getTally = tallyResult

  def getDecryptionSharesR1ForProposal(proposalId: Int): Seq[C1Share] =
    c1SharesR1.flatMap(share => share._2.collect { case b if b.proposalId == proposalId => b }).toSeq
  def getDecryptionSharesR2ForProposal(proposalId: Int): Seq[C1Share] =
    c1SharesR2.flatMap(share => share._2.collect { case b if b.proposalId == proposalId => b }).toSeq


  protected def apply(tx: TreasuryTransaction): Try[Unit] = tx match {
      case t: RegisterTransaction => Try { t.role match {
        case Role.Expert => expertsPubKeys = expertsPubKeys :+ t.pubKey
        case Role.Voter => votersPubKeys = votersPubKeys :+ t.pubKey
      }}
      case t: CommitteeRegisterTransaction => Try {
        committeePubKeys = committeePubKeys :+ (t.pubKey, t.proxyPubKey)
      }
      case t: ProposalTransaction => Try {
        proposals = proposals :+ Proposal(t.name, t.requestedSum, t.recipient)
      }
      case t: BallotTransaction => Try { t.voterType match {
        case VoterType.Voter =>
          val id = votersPubKeys.indexOf(t.pubKey)
          require(id >= 0, "Voter isn't found")
          votersBallots = votersBallots + (id -> t.ballots.map(_.asInstanceOf[VoterBallot]))
        case VoterType.Expert =>
          val id = expertsPubKeys.indexOf(t.pubKey)
          require(id >= 0, "Expert isn't found")
          expertsBallots = expertsBallots + (id -> t.ballots.map(_.asInstanceOf[ExpertBallot]))
      }}
      case t: DecryptionShareTransaction => Try {
        val id = getCommitteeSigningKeys.indexOf(t.pubKey)
        require(id >= 0, "Committee member isn't found")
        t.round match {
          case DecryptionRound.R1 => c1SharesR1 = c1SharesR1 + (id -> t.c1Shares)
          case DecryptionRound.R2 => c1SharesR2 = c1SharesR2 + (id -> t.c1Shares)
        }
      }
      case t: PaymentTransaction => Try(log.info(s"Payment tx was applied ${tx.json}"))
  }

  def apply(block: HybridBlock, history: HybridHistory): Try[TreasuryState] = Try {
    val blockHeight = history.storage.heightOf(block.id).get
    validate(block, blockHeight).get

    block match {
      case b:PosBlock => {
        log.info(s"TreasuryState: applying PoS block ${block.encodedId} at height ${history.storage.heightOf(block.id)}")

        val trTxs = b.transactions.collect { case t: TreasuryTransaction => t }
        trTxs.foreach(tx => apply(tx).get)
        version = VersionTag @@ block.id
      }
      case _ => this
    }

    val epochHeight = history.storage.heightOf(block.id).get.toInt % TreasuryManager.EPOCH_LEN
    updateState(epochHeight)
  }

  private def updateState(epochHeight: Int): TreasuryState = {
    epochHeight match {
      case TreasuryManager.DISTR_KEY_GEN_RANGE.end =>
        if (committeePubKeys.nonEmpty)
          sharedPublicKey = Some(committeePubKeys.map(_._2).foldLeft(cs.infinityPoint)((sum,next) => sum.add(next)))
        else log.warn("No committee members found!")

      case TreasuryManager.VOTING_DECRYPTION_R1_RECOVERY_RANGE.end =>
        /* We can calculate delegations ONLY IF we have valid decryption shares from ALL committee members
        *  TODO: recover secret keys (and corresponding decryption shares) of the faulty CMs by KeyShares submissions */
        if (c1SharesR1.size == committeePubKeys.size) {
          val deleg = proposals.indices.map { i =>
            val shares = getDecryptionSharesR1ForProposal(i)
            assert(shares.size == committeePubKeys.size)
            val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))
            (i -> decryptor.computeDelegations(shares.map(_.decryptedC1.map(_._1))))
          }
          delegations = Some(deleg.toMap)
        }

      case TreasuryManager.VOTING_DECRYPTION_R2_RECOVERY_RANGE.end =>
      /* We can decrypt final voting result ONLY IF we have valid decryption shares from ALL committee members
      *  TODO: recover secret keys (and corresponding decryption shares) of the faulty CMs by KeyShares submissions */
        if (c1SharesR2.size == committeePubKeys.size && getDelegations.isDefined) {
          val result = proposals.indices.foreach { i =>
            val shares = getDecryptionSharesR2ForProposal(i).map(_.decryptedC1.map(_._1))
            val delegations = getDelegations.get(i)
            assert(shares.size == committeePubKeys.size)
            assert(delegations.size == expertsPubKeys.size)
            val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))
            val tally = decryptor.computeTally(shares, delegations)
            if (tally.isSuccess)
              tallyResult = tallyResult + (i -> tally.get)
          }
        }

      case _ =>
    }

    this
  }

  def validate(block: HybridBlock, blockHeight: Long): Try[Unit] = Try {
    block match {
      case _:PowBlock => Unit
      case b:PosBlock => {
        val trTxs = b.transactions.collect{case t:TreasuryTransaction => t}

        if ((blockHeight % TreasuryManager.PAYMENT_BLOCK_HEIGHT) == 0)
          require(trTxs.count(t => t.isInstanceOf[PaymentTransaction]) == 1, "Invalid block: PaymentTransaction is absent")

        val validator = new TreasuryTxValidator(this, blockHeight)
        trTxs.foreach(validator.validate(_).get)
      }
    }
  }

  def rollback(to: VersionTag): Try[TreasuryState] = Try {
    if (to sameElements version) this
    else throw new UnsupportedOperationException("Deep rollback is not supported")
  }

  def getPayments: Try[Seq[(PublicKey25519Proposition, Value)]] = Try {
    val approvedProposals = getTally.filter(p => p._2.yes.compareTo(p._2.no) > 0).toSeq.sortBy(_._1).map(p => getProposals(p._1))
    var proposalsBudget = TreasuryManager.PROPOSALS_BUDGET
    var payments = Seq[(PublicKey25519Proposition, Value)]()
    approvedProposals.foreach { p =>
      if (p.requestedSum <= proposalsBudget) {
        payments = payments :+ (p.recipient, p.requestedSum)
      }
    }

    // TODO: payment per voter should be based on deposit amount
    val voters = getVotersBallots.toSeq.sortBy(_._1).map(v => getVotersSigningKeys(v._1))
    if (voters.size > 0) {
      val paymentPerVoter = Value @@ (TreasuryManager.VOTERS_BUDGET / voters.size).round
      if (paymentPerVoter > 0)
        payments = payments ++ voters.map(v => (v, paymentPerVoter))
    }

    // TODO: payment per expert should be based on the number of delegations
    val experts = getExpertsBallots.toSeq.sortBy(_._1).map(v => getExpertsSigningKeys(v._1))
    if (experts.size > 0) {
      val paymentPerExpert = Value @@ (TreasuryManager.EXPERTS_BUDGET / experts.size).round
      if (paymentPerExpert > 0)
        payments = payments ++ experts.map(v => (v, paymentPerExpert))
    }

    val committee = getDecryptionSharesR2.toSeq.sortBy(_._1).map(v => getCommitteeSigningKeys(v._1))
    if (committee.size > 0) {
      val paymentPerCommittee = Value @@ (TreasuryManager.COMMITTEE_BUDGET / committee.size).round
      if (paymentPerCommittee > 0)
        payments = payments ++ committee.map(v => (v, paymentPerCommittee))
    }

    payments
  }
}

object TreasuryState {

  def generate(history: HybridHistory): Try[TreasuryState] = Try {

    val currentHeight = history.storage.height.toInt
    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN

    val epochBlocksIds = history.lastBlockIds(history.bestBlock, currentEpochHeight + 1)

    val state = TreasuryState(epochNum)

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => state.apply(history.modifierById(blockId).get, history).get)
    state
  }

  /**
    * Generate TreasuryState for the specific epoch. Usefull for testing purposes to see past treasury epochs.
    *
    * @param history
    * @param epochId
    * @return Success(TreasuryState) or Failure(e) in case it can't be derived for provided epochId
    */
  def generate(history: HybridHistory, epochId: Int): Try[TreasuryState] = Try {
    val currentHeight = history.storage.height.toInt
    val currentEpochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN
    require(epochId >= 0 && epochId <= currentEpochNum, "Wrong epoch id")

    val epochBlocksIds =
      if (epochId == currentEpochNum) {
        history.lastBlockIds(history.bestBlock, currentEpochHeight + 1)
      } else if (epochId == 0) {
        val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
        history.lastBlockIds(history.bestBlock, count).take(TreasuryManager.EPOCH_LEN - 2) // -2 cause history don't give genesis blocks
      } else {
        val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
        history.lastBlockIds(history.bestBlock, count).take(TreasuryManager.EPOCH_LEN)
      }

    val state = TreasuryState(epochId)

    /* parse all blocks in the epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => state.apply(history.modifierById(blockId).get, history).get)
    state
  }
}
