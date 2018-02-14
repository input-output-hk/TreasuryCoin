package examples.hybrid.state

import examples.commons.Value
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction._
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import scorex.core.{ModifierId, VersionTag}
import treasury.crypto.core.PubKey
import treasury.crypto.keygen.KeyShares
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.voting.ballots.{ExpertBallot, VoterBallot}

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
  private var c1SharesR2: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR2: Map[Int, KeyShares] = Map() // committeeMemberId -> KeyShares

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

  def getDecryptionSharesR1 = c1SharesR1
  def getKeyRecoverySharesR1 = keyRecoverySharesR1
  def getDecryptionSharesR2 = c1SharesR2
  def getKeyRecoverySharesR2 = keyRecoverySharesR2


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
    epochHeight match {
      case TreasuryManager.DISTR_KEY_GEN_RANGE.end =>
        if (committeePubKeys.nonEmpty)
          sharedPublicKey = Some(committeePubKeys.map(_._2).foldLeft(cs.infinityPoint)((sum,next) => sum.add(next)))
        else
          log.warn("No committee members found!")
      case _ =>
    }

    this
  }

  def validate(block: HybridBlock, blockHeight: Long): Try[Unit] = Try {
    block match {
      case _:PowBlock => Unit
      case b:PosBlock => {
        val trTxs = b.transactions.collect{case t:TreasuryTransaction => t}
        val validator = new TreasuryTxValidator(this, blockHeight)
        trTxs.foreach(validator.validate(_).get)
      }
    }
  }

  def rollback(to: VersionTag): Try[TreasuryState] = Try {
    if (to sameElements version) this
    else throw new UnsupportedOperationException("Deep rollback is not supported")
  }
}

object TreasuryState {

  def generate(history: HybridHistory): Try[TreasuryState] = Try {

    val currentHeight = history.storage.heightOf(history.storage.bestPosId).get.toInt
    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN

    val epochBlocksIds = history.lastBlockIds(history.modifierById(history.storage.bestPosId).get, currentEpochHeight + 1)

    val state = TreasuryState(epochNum)

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => state.apply(history.modifierById(blockId).get, history).get)
    state
  }
}
