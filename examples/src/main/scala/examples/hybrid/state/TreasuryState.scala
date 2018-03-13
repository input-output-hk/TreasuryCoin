package examples.hybrid.state

import java.math.BigInteger

import com.google.common.primitives.Bytes
import examples.commons.{PublicKey25519NoncedBox, Value}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.TreasuryManager.Role.Role
import examples.hybrid.blocks.{HybridBlock, PosBlock, PowBlock}
import examples.hybrid.history.HybridHistory
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.transaction.DKG._
import examples.hybrid.transaction.DecryptionShareTransaction.DecryptionRound
import examples.hybrid.transaction._
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import scorex.core.{ModifierId, VersionTag}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, Digest32}
import treasury.crypto.core.{PubKey, SimpleIdentifier}
import treasury.crypto.keygen.{DecryptionManager, DistrKeyGen, KeyShares, RoundsData}
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.keygen.datastructures.round1.R1Data
import treasury.crypto.keygen.datastructures.round2.R2Data
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.keygen.datastructures.round4.R4Data
import treasury.crypto.keygen.datastructures.round5_1.R5_1Data
import treasury.crypto.voting.Tally
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.util.{Failure, Success, Try}

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
  val crs_h = cs.basePoint.multiply(BigInteger.valueOf(5)) // common CRS parameter (temporary)

  private var version: VersionTag = VersionTag @@ (ModifierId @@ Array.fill(32)(0: Byte))
  private var proposals: List[Proposal] = List()
  private var expertsInfo: List[ExpertInfo] = List()
  private var votersInfo: List[VoterInfo] = List()
  private var committeeInfo: List[CommitteeInfo] = List()

  private var randomness: Array[Byte] = Array.fill[Byte](32)(234.toByte) // TODO: change with a real randomness

  private var sharedPublicKey: Option[PubKey] = None
  private var votersBallots: Map[Int, Seq[VoterBallot]] = Map() // voterId -> Seq(ballot)
  private var expertsBallots: Map[Int, Seq[ExpertBallot]] = Map() // expertId -> Seq(ballot)

  private var c1SharesR1: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR1: Map[Int, KeyShares] = Map() // committeeMemberId -> KeyShares
  private var delegations: Option[Map[Int, Seq[BigInteger]]] = None  // delegations for all proposals
  private var c1SharesR2: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR2: Map[Int, KeyShares] = Map() // committeeMemberId -> KeyShares

  private var tallyResult: Map[Int, Tally.Result] = Map() // proposalId -> voting result

  private var DKGr1Data: Map[Int, R1Data] = Map()
  private var DKGr2Data: Map[Int, R2Data] = Map()
  private var DKGr3Data: Map[Int, R3Data] = Map()
  private var DKGr4Data: Map[Int, R4Data] = Map()
  private var DKGr5Data: Map[Int, R5_1Data] = Map()

  def getDKGr1Data = DKGr1Data
  def getDKGr2Data = DKGr2Data
  def getDKGr3Data = DKGr3Data
  def getDKGr4Data = DKGr4Data
  def getDKGr5Data = DKGr5Data

  def getVotersInfo = votersInfo
  def getExpertsInfo = expertsInfo
  def getCommitteeInfo = committeeInfo
  def getApprovedCommitteeInfo = committeeInfo.filter(_.approved)

  def getSigningKeys(role: Role): List[PublicKey25519Proposition] = role match {
    case Role.Committee => getCommitteeInfo.map(_.signingKey)
    case Role.Expert => getExpertsInfo.map(_.signingKey)
    case Role.Voter => getVotersInfo.map(_.signingKey)
  }

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


  protected def apply(tx: TreasuryTransaction): Try[Unit] = {

    def commonVerificationForDKGTxs(id: Long, t: SignedTreasuryTransaction) {
      require(id >= 0, "Committee member isn't found")
      require(t.semanticValidity.isSuccess, "Transaction isn't semantically valid!")
    }

    tx match {
      case t: RegisterTransaction => Try {
        val deposit = t.newBoxes.find(_.proposition == TreasuryManager.VOTER_DEPOSIT_ADDR).get
        t.role match {
          case Role.Expert => expertsInfo = expertsInfo :+ ExpertInfo(t.pubKey, deposit, t.paybackAddr)
          case Role.Voter => votersInfo = votersInfo :+ VoterInfo(t.pubKey, deposit, t.paybackAddr)
        }
        if (t.committeeProxyPubKey.isDefined) {
          val committeeDeposit = t.newBoxes.find(_.proposition == TreasuryManager.COMMITTEE_DEPOSIT_ADDR).get
          committeeInfo = committeeInfo :+ CommitteeInfo(true, t.committeeProxyPubKey.get, t.pubKey, committeeDeposit, t.paybackAddr)
        }
      }
      case t: ProposalTransaction => Try {
        proposals = proposals :+ Proposal(t.name, t.requestedSum, t.recipient)
      }
      case t: BallotTransaction => Try {
        t.voterType match {
          case VoterType.Voter =>
            val id = getVotersInfo.map(_.signingKey).indexOf(t.pubKey)
            require(id >= 0, "Voter isn't found")
            votersBallots = votersBallots + (id -> t.ballots.map(_.asInstanceOf[VoterBallot]))
          case VoterType.Expert =>
            val id = getExpertsInfo.map(_.signingKey).indexOf(t.pubKey)
            require(id >= 0, "Expert isn't found")
            expertsBallots = expertsBallots + (id -> t.ballots.map(_.asInstanceOf[ExpertBallot]))
        }
      }
      case t: DecryptionShareTransaction => Try {
        val id = getApprovedCommitteeInfo.map(_.signingKey).indexOf(t.pubKey)
        require(id >= 0, "Committee member isn't found")
        t.round match {
          case DecryptionRound.R1 => c1SharesR1 = c1SharesR1 + (id -> t.c1Shares)
          case DecryptionRound.R2 => c1SharesR2 = c1SharesR2 + (id -> t.c1Shares)
        }
      }
      case t: DKGr1Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        commonVerificationForDKGTxs(id, t)
        DKGr1Data += (id -> t.r1Data)
      }
      case t: DKGr2Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        commonVerificationForDKGTxs(id, t)
        DKGr2Data += (id -> t.r2Data)
      }
      case t: DKGr3Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        commonVerificationForDKGTxs(id, t)
        DKGr3Data += (id -> t.r3Data)
      }
      case t: DKGr4Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        commonVerificationForDKGTxs(id, t)
        DKGr4Data += (id -> t.r4Data)
      }
      case t: DKGr5Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        commonVerificationForDKGTxs(id, t)
        DKGr5Data += (id -> t.r5_1Data)
      }
      case t: PaymentTransaction => Try(log.info(s"Payment tx was applied ${tx.json}"))
    }
  }

  def apply(block: HybridBlock, history: HybridHistory, state: Option[HBoxStoredState] = None): Try[TreasuryState] = Try {
    validate(block, history, state).get

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

  def validate(block: HybridBlock, history: HybridHistory, state: Option[HBoxStoredState]): Try[Unit] = Try {
    val blockHeight = history.storage.heightOf(block.id).get

    block match {
      case _:PowBlock => Unit
      case b:PosBlock => {
        val trTxs = b.transactions.collect{case t:TreasuryTransaction => t}

        if ((blockHeight % TreasuryManager.EPOCH_LEN) == TreasuryManager.PAYMENT_BLOCK_HEIGHT)
          require(trTxs.count(t => t.isInstanceOf[PaymentTransaction]) == 1, "Invalid block: PaymentTransaction is absent")

        val validator = new TreasuryTxValidator(this, blockHeight, Some(history), state)
        trTxs.foreach(validator.validate(_).get)
      }
    }
  }

  def rollback(to: VersionTag): Try[TreasuryState] = Try {
    if (to sameElements version) this
    else throw new UnsupportedOperationException("Deep rollback is not supported")
  }

  private def updateState(epochHeight: Int): TreasuryState = {
    epochHeight match {

      case h if h >= TreasuryManager.DISTR_KEY_GEN_R5_RANGE.end && sharedPublicKey.isEmpty =>

        log.info("Computing shared public key")

        if (getApprovedCommitteeInfo.nonEmpty){

          val committeeMembersPubKeys = getApprovedCommitteeInfo.map(_.proxyKey)
          val memberIdentifier = new SimpleIdentifier(committeeMembersPubKeys)
          val roundsData = RoundsData(
            getDKGr1Data.values.toSeq,
            getDKGr2Data.values.toSeq,
            getDKGr3Data.values.toSeq,
            getDKGr4Data.values.toSeq,
            getDKGr5Data.values.toSeq
          )
          DistrKeyGen.getSharedPublicKey(cs, committeeMembersPubKeys, memberIdentifier, roundsData) match {
            case Success(sharedPubKey) =>
              sharedPublicKey = Some(cs.decodePoint(sharedPubKey))
              log.info(s"Shared public key is: ${Base58.encode(sharedPublicKey.get.getEncoded(true))}")

            case Failure(e) => log.error(e.getMessage)
          }
        } else log.warn("No committee members found!")

      case TreasuryManager.EXPERT_REGISTER_RANGE.end => selectApprovedCommittee()
      case TreasuryManager.VOTING_DECRYPTION_R1_RECOVERY_RANGE.end => calculateDelegations()
      case TreasuryManager.VOTING_DECRYPTION_R2_RECOVERY_RANGE.end => calculateTallyResult()

      case _ =>
    }

    this
  }

  private def selectApprovedCommittee(): Unit = {
    // TODO: inefficient ordering but let it be ok for now, cause we should not have a lot of members
    implicit val ordering = Ordering.by((_: Digest32).toIterable)

    val approvedCommittee = getCommitteeInfo.map { c =>
      val hash = Blake2b256(Bytes.concat(c.proxyKey.getEncoded(true), c.signingKey.bytes, randomness))
      (c, hash)
    }.sortBy(_._2).take(TreasuryManager.COMMITTEE_SIZE).map(_._1.signingKey)

    committeeInfo = committeeInfo.map(c => c.copy(approved = approvedCommittee.contains(c.signingKey)))
  }

  private def calculateDelegations(): Unit = {
    /* We can calculate delegations ONLY IF we have valid decryption shares from ALL committee members
    *  TODO: recover secret keys (and corresponding decryption shares) of the faulty CMs by KeyShares submissions */
    if (c1SharesR1.size == getApprovedCommitteeInfo.size) {
      val deleg = proposals.indices.map { i =>
        val shares = getDecryptionSharesR1ForProposal(i)
        assert(shares.size == getApprovedCommitteeInfo.size)
        val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))
        (i -> decryptor.computeDelegations(shares.map(_.decryptedC1.map(_._1))))
      }
      delegations = Some(deleg.toMap)
    }
  }

  private def calculateTallyResult(): Unit = {
    /* We can decrypt final voting result ONLY IF we have valid decryption shares from ALL committee members
    *  TODO: recover secret keys (and corresponding decryption shares) of the faulty CMs by KeyShares submissions */
    if (c1SharesR2.size == getApprovedCommitteeInfo.size && getDelegations.isDefined) {
      val result = proposals.indices.foreach { i =>
        val shares = getDecryptionSharesR2ForProposal(i).map(_.decryptedC1.map(_._1))
        val delegations = getDelegations.get(i)
        assert(shares.size == getApprovedCommitteeInfo.size)
        assert(delegations.size == getExpertsInfo.size)
        val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))
        val tally = decryptor.computeTally(shares, delegations)
        if (tally.isSuccess)
          tallyResult = tallyResult + (i -> tally.get)
      }
    }
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

    val payedVoters = getVotersBallots.map(v => getVotersInfo(v._1))
    if (payedVoters.size > 0) {
      val totalVotedStake = payedVoters.map(_.depositBox.value.toDouble).sum
      for (v <- payedVoters) {
        val amount = (v.depositBox.value / totalVotedStake) * TreasuryManager.VOTERS_BUDGET
        if (amount >= 1.0)
          payments = payments :+ (v.paybackAddr, Value @@ amount.toLong)
      }
    }

    val payedExperts = getExpertsBallots.map(v => getExpertsInfo(v._1))
    val delegations = getDelegations.getOrElse(Map())
    val totalDelegations = delegations.map(_._2.map(_.longValue).sum).toSeq.sum
    if (payedExperts.size > 0 && totalDelegations > 0) {
      for (v <- payedExperts) {
        val expertId = getExpertsInfo.indexOf(v)
        val delegatedToExpert = delegations.map(_._2(expertId).longValue).sum.toDouble
        val amount = (delegatedToExpert / totalDelegations) * TreasuryManager.EXPERTS_BUDGET
        if (amount >= 1.0)
          payments = payments :+ (v.paybackAddr, Value @@ amount.toLong)
      }
    }

    val committee = getDecryptionSharesR2.map(v => getApprovedCommitteeInfo(v._1).paybackAddr)
    if (committee.size > 0) {
      val paymentPerCommittee = Value @@ (TreasuryManager.COMMITTEE_BUDGET / committee.size).round
      if (paymentPerCommittee > 0)
        payments = payments ++ committee.map(v => (v, paymentPerCommittee))
    }

    payments
  }

  def getDepositPaybacks(history: HybridHistory, state: HBoxStoredState):
    Try[Seq[(PublicKey25519NoncedBox, PublicKey25519Proposition)]] = Try {

    // since we are going to pay back to parties that participated in the previous epochs,
    // first define the number of an epoch which parties will be reimbursed
    val paybackEpoch = epochNum - TreasuryManager.DEPOSIT_LOCK_PERIOD
    require(paybackEpoch >= 0, "Payback isn't allowed")

    val (voters, experts, committee) =
      if (paybackEpoch == epochNum)
        (getVotersInfo, getExpertsInfo, getCommitteeInfo)
      else
        TreasuryState.generatePartiesInfo(history, paybackEpoch).get

    val partiesInfo = voters ++ experts ++ committee

    // Filter those parties whose deposits are not accessible. It can be because of the punishement or deposit renewal
    val paybackParties = partiesInfo.filter(box => state.closedBox(box.depositBox.id).isDefined)
    paybackParties.map(p => (p.depositBox, p.paybackAddr))
  }
}

object TreasuryState {

  /**
    * Recovers info about voters/experts/committies for old epochs.
    * It is done by partial reconstruction of the TreasuryState for the required epoch.
    *
    * @param history history
    * @param epochId epochid
    * @return Success(seq) where seq is a sequence of triplets with parties info
    */
  def generatePartiesInfo(history: HybridHistory, epochId: Int):
    Try[(Seq[VoterInfo], Seq[ExpertInfo], Seq[CommitteeInfo])] = Try {

    val currentHeight = history.storage.height.toInt
    val currentEpochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN
    require(epochId >= 0 && epochId < currentEpochNum, "Parties info can be requested only for past epochs. Use getInfo methods directly for the current epoch.")

    val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
    // we should take all registration blocks
    val epochBlocksIds = history.lastBlockIds(history.bestBlock, count).take(TreasuryManager.EXPERT_REGISTER_RANGE.end)

    val trState = TreasuryState(epochId)

    /* reconstruct necessary part of the TreasuryState */
    epochBlocksIds.foreach(blockId => trState.apply(history.modifierById(blockId).get, history).get)

    (trState.getVotersInfo, trState.getExpertsInfo, trState.getCommitteeInfo)
  }

  /**
    * Generate TreasuryState for the current epoch. Note that state is optional because it is needed only to validate
    * PaymentTransaction. In cases when it is not needed state can be None.
    *
    * @param history history
    * @param state minimal state
    * @return
    */
  def generate(history: HybridHistory, state: Option[HBoxStoredState] = None): Try[TreasuryState] = Try {

    CommitteeMember.stopMember()

    val currentHeight = history.storage.height.toInt
    val epochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN

    val epochBlocksIds = history.lastBlockIds(history.bestBlock, currentEpochHeight + 1)

    val trState = TreasuryState(epochNum)

    /* parse all blocks in the current epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => trState.apply(history.modifierById(blockId).get, history, state).get)
    trState
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

    val trState = TreasuryState(epochId)

    /* parse all blocks in the epoch and extract all treasury transactions */
    epochBlocksIds.foreach(blockId => trState.apply(history.modifierById(blockId).get, history).get)
    trState
  }
}

case class Proposal(name: String, requestedSum: Value, recipient: PublicKey25519Proposition)

abstract class PartyInfo {
  val signingKey: PublicKey25519Proposition
  val depositBox: PublicKey25519NoncedBox
  val paybackAddr: PublicKey25519Proposition
}

case class CommitteeInfo(approved: Boolean, // we allow only constant-size committee, so not all registered parities will become approved CM
                         proxyKey: PubKey,
                         signingKey: PublicKey25519Proposition,
                         depositBox: PublicKey25519NoncedBox,
                         paybackAddr: PublicKey25519Proposition) extends PartyInfo

case class VoterInfo(signingKey: PublicKey25519Proposition,
                     depositBox: PublicKey25519NoncedBox,
                     paybackAddr: PublicKey25519Proposition) extends PartyInfo

case class ExpertInfo(signingKey: PublicKey25519Proposition,
                      depositBox: PublicKey25519NoncedBox,
                      paybackAddr: PublicKey25519Proposition) extends PartyInfo