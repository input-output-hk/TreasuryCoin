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
import examples.hybrid.transaction.RecoveryShareTransaction.RecoveryRound
import examples.hybrid.transaction._
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.utils.ScorexLogging
import scorex.core.{ModifierId, VersionTag}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, Digest32}
import treasury.crypto.core._
import treasury.crypto.decryption.{DecryptionManager, RandomnessGenManager}
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.keygen.datastructures.round1.R1Data
import treasury.crypto.keygen.datastructures.round2.R2Data
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.keygen.datastructures.round4.{OpenedShare, R4Data}
import treasury.crypto.keygen.datastructures.round5_1.R5_1Data
import treasury.crypto.keygen.{DistrKeyGen, RoundsData}
import treasury.crypto.voting.Tally
import treasury.crypto.voting.ballots.{Ballot, ExpertBallot, VoterBallot}

import scala.collection.mutable
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

  private var randomness: Array[Byte] = Array.fill[Byte](8)(1.toByte)
  private var submittedRandomnessForNextEpoch: Map[Int, Ciphertext] = Map() // committee member id -> encrypted randomness
  private var decryptedRandomness: Map[PublicKey25519Proposition, Point] = Map() // committee member signing pub key -> random point
  private var keyRecoverySharesRandGen: mutable.Map[Int, Seq[OpenedShare]] = mutable.Map() // recoveredCommitteeMemberId -> opened shares
  private var disqualifiedCommitteeMembersAfterRandGen: Seq[CommitteeInfo] = Seq()
  private var recoveredRandomness: Seq[Point] = Seq()

  private var sharedPublicKey: Option[PubKey] = None

  private var disqualifiedCommitteeMembersAfterDKG: Seq[CommitteeInfo] = Seq()
  private var disqualifiedCommitteeMembersAfterDecryptionR1: Seq[CommitteeInfo] = Seq()
  private var disqualifiedCommitteeMembersAfterDecryptionR2: Seq[CommitteeInfo] = Seq()
  private var recoveredKeysOfDisqualifiedCommitteeMembers: Seq[(PubKey, PrivKey)] = Seq()

  private var votersBallots: Map[Int, Seq[VoterBallot]] = Map() // voterId -> Seq(ballot)
  private var expertsBallots: Map[Int, Seq[ExpertBallot]] = Map() // expertId -> Seq(ballot)

  private var c1SharesR1: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR1: mutable.Map[Int, Seq[OpenedShare]] = mutable.Map() // recoveredCommitteeMemberId -> opened shares
  private var delegations: Option[Map[Int, Seq[BigInteger]]] = None  // delegations for all proposals
  private var c1SharesR2: Map[Int, Seq[C1Share]] = Map() // committeeMemberId -> Seq(C1Share)
  private var keyRecoverySharesR2: mutable.Map[Int, Seq[OpenedShare]] = mutable.Map() // recoveredCommitteeMemberId -> opened shares

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
  def getParticipatedCommitteeInfo = committeeInfo.filter(_.participated)

  def getDisqualifiedAfterDKGCommitteeInfo = disqualifiedCommitteeMembersAfterDKG
  def getDisqualifiedAfterDecryptionR1CommitteeInfo = disqualifiedCommitteeMembersAfterDecryptionR1
  def getDisqualifiedAfterDecryptionR2CommitteeInfo = disqualifiedCommitteeMembersAfterDecryptionR2
  def getAllDisqualifiedCommitteeInfo = getDisqualifiedAfterDKGCommitteeInfo ++ getDisqualifiedAfterRandGenCommitteeInfo ++
    getDisqualifiedAfterDecryptionR1CommitteeInfo ++ getDisqualifiedAfterDecryptionR2CommitteeInfo
  def getRecoveredKeys = recoveredKeysOfDisqualifiedCommitteeMembers

  def getSubmittedRandomnessForNextEpoch = submittedRandomnessForNextEpoch
  def getDecryptedRandomness = decryptedRandomness
  def getRecoveredRandomness = recoveredRandomness
  def getRandomness = randomness
  def getKeyRecoverySharesRandGen = keyRecoverySharesRandGen
  def getDisqualifiedAfterRandGenCommitteeInfo = disqualifiedCommitteeMembersAfterRandGen

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

    tx match {
      case t: RegisterTransaction => Try {
        val deposit = t.newBoxes.find(_.proposition == TreasuryManager.VOTER_DEPOSIT_ADDR).get
        t.role match {
          case Role.Expert => expertsInfo = expertsInfo :+ ExpertInfo(t.pubKey, deposit, t.paybackAddr)
          case Role.Voter => votersInfo = votersInfo :+ VoterInfo(t.pubKey, deposit, t.paybackAddr)
        }
        if (t.committeeProxyPubKey.isDefined) {
          val committeeDeposit = t.newBoxes.find(_.proposition == TreasuryManager.COMMITTEE_DEPOSIT_ADDR).get
          committeeInfo = committeeInfo :+ CommitteeInfo(true, true, t.committeeProxyPubKey.get, t.pubKey, committeeDeposit, t.paybackAddr)
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
      case t: RecoveryShareTransaction => Try {
        t.round match {
          case RecoveryRound.DecryptionR1 => t.openedShares.foreach { s =>
            val updatedShares = keyRecoverySharesR1.get(s.violatorId).getOrElse(Seq()) :+ s.openedShare
            keyRecoverySharesR1(s.violatorId) = updatedShares
          }
          case RecoveryRound.DecryptionR2 => t.openedShares.foreach { s =>
            val updatedShares = keyRecoverySharesR2.get(s.violatorId).getOrElse(Seq()) :+ s.openedShare
            keyRecoverySharesR2(s.violatorId) = updatedShares
          }
          case RecoveryRound.Randomness => t.openedShares.foreach { s =>
            val updatedShares = keyRecoverySharesRandGen.get(s.violatorId).getOrElse(Seq()) :+ s.openedShare
            keyRecoverySharesRandGen(s.violatorId) = updatedShares
          }
        }
      }
      case t: DKGr1Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        DKGr1Data += (id -> t.r1Data)
      }
      case t: DKGr2Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        DKGr2Data += (id -> t.r2Data)
      }
      case t: DKGr3Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        DKGr3Data += (id -> t.r3Data)
      }
      case t: DKGr4Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        DKGr4Data += (id -> t.r4Data)
      }
      case t: DKGr5Transaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        DKGr5Data += (id -> t.r5_1Data)
      }
      case t: RandomnessTransaction => Try {
        val id = getApprovedCommitteeInfo.indexWhere(_.signingKey == t.pubKey)
        require(id >= 0, "Committee member isn't found")
        submittedRandomnessForNextEpoch += (id -> t.encryptedRandomness)
      }
      case t: RandomnessDecryptionTransaction => Try {
        decryptedRandomness += (t.pubKey -> t.decryptedRandomness.randomness)
      }
      case t: PaymentTransaction => Try(log.info(s"Payment tx was applied ${tx.json}"))
      case t: PenaltyTransaction => Try(log.info(s"Penalty tx was applied ${tx.json}"))
    }
  }

  def apply(block: HybridBlock, history: HybridHistory, state: Option[HBoxStoredState] = None): Try[TreasuryState] = Try {
    validate(block, history, state).get

    block match {
      case b:PosBlock => {
        //log.info(s"TreasuryState: applying PoS block ${block.encodedId} at height ${history.storage.heightOf(block.id)}")

        val trTxs = b.transactions.collect { case t: TreasuryTransaction => t }
        trTxs.foreach(tx => apply(tx).get)
        version = VersionTag @@ block.id
      }
      case _ => this
    }

    val epochHeight = history.storage.heightOf(block.id).get.toInt % TreasuryManager.EPOCH_LEN
    updateState(epochHeight, history)
  }

  def validate(block: HybridBlock, history: HybridHistory, state: Option[HBoxStoredState]): Try[Unit] = Try {
    val blockHeight = history.storage.heightOf(block.id).get

    block match {
      case _:PowBlock => Unit
      case b:PosBlock => {
        val trTxs = b.transactions.collect{case t:TreasuryTransaction => t}

        val epochHeight = blockHeight % TreasuryManager.EPOCH_LEN
        if (epochHeight == TreasuryManager.PAYMENT_BLOCK_HEIGHT)
          require(trTxs.count(t => t.isInstanceOf[PaymentTransaction]) == 1, "Invalid block: PaymentTransaction is absent")
        if (epochHeight == TreasuryManager.PENALTY_BLOCK_HEIGHT)
          require(trTxs.count(t => t.isInstanceOf[PenaltyTransaction]) == 1, "Invalid block: PenaltyTransaction is absent")

        val validator = new TreasuryTxValidator(this, blockHeight, Some(history), state)
        trTxs.foreach(validator.validate(_).get)
      }
    }
  }

  def rollback(to: VersionTag, history: HybridHistory): Try[TreasuryState] = Try {
    val posBlockVersion = history.modifierById(ModifierId @@ to).get match {
      case b: PosBlock => b.id
      case b: PowBlock => b.prevPosId
    }
    if (posBlockVersion sameElements version) this
    else throw new UnsupportedOperationException("Deep rollback is not supported")
  }

  private def updateState(epochHeight: Int, history: HybridHistory): TreasuryState = {
    epochHeight match {
      case TreasuryManager.RANDOMNESS_DECRYPTION_RANGE.end =>
        retrieveDisqualifiedAfterRandGen(history)
      case TreasuryManager.RANDOMNESS_DECRYPTION_RECOVERY_RANGE.end =>
        recoverRandomness(history)
        updateRandomness()
        selectApprovedCommittee()
      case TreasuryManager.DISTR_KEY_GEN_R5_RANGE.end =>
        retrieveSharedPublicKey() match {
          case Success(_) =>
          case Failure(e) => log.error("Failed to generate shared key", e)
        }
        retrieveDisqualifiedAfterDKG()
      case TreasuryManager.VOTING_DECRYPTION_R1_RANGE.end =>
        updateDisqualifiedAfterDecryptionR1()
      case TreasuryManager.VOTING_DECRYPTION_R1_RECOVERY_RANGE.end =>
        retrieveKeysOfDisqualified(getKeyRecoverySharesR1.toMap)
        calculateDelegations() match {
          case Success(_) => log.info("Delegations are successfully calculated")
          case Failure(e) => log.error("Failed to calculate delegations", e)
        }
      case TreasuryManager.VOTING_DECRYPTION_R2_RANGE.end =>
        updateDisqualifiedAfterDecryptionR2()
      case TreasuryManager.VOTING_DECRYPTION_R2_RECOVERY_RANGE.end =>
        retrieveKeysOfDisqualified(getKeyRecoverySharesR2.toMap)
        calculateTallyResult() match {
          case Success(_) => log.info("Tally is successfully calculated")
          case Failure(e) => log.error("Failed to calculate Tally", e)
        }
      case _ =>
    }

    this
  }

  private def retrieveDisqualifiedAfterRandGen(history: HybridHistory): Unit = Try {
    val prevCommittee = TreasuryState.generatePartiesInfo(history, epochNum - 1).get._3.filter(_.approved)
    val submitters = TreasuryState.generateRandomnessSubmission(history, epochNum - 1).get.map(_._1)
    val submittersWhoDecrypted = getDecryptedRandomness.keys
    val disqualified = submitters.filter(s => !submittersWhoDecrypted.exists(k => k == s))

    disqualifiedCommitteeMembersAfterRandGen = prevCommittee.filter(c => disqualified.contains(c.signingKey))
  }

  private def recoverRandomness(history: HybridHistory): Unit = Try {
    val prevCommittee = TreasuryState.generatePartiesInfo(history, epochNum - 1).get._3.filter(_.approved)
    val randomnessSubmission = TreasuryState.generateRandomnessSubmission(history, epochNum - 1).get
    val prevR3Data = TreasuryState.generateR3Data(history, epochNum - 1).get

    keyRecoverySharesRandGen.foreach { s =>
      val violatorInfo = prevCommittee(s._1)
      val violatorPubKey = TreasuryManager.cs.decodePoint(prevR3Data.find(_.issuerID == s._1).get.commitments(0))
      val privKeyOpt = DistrKeyGen.recoverPrivateKeyByOpenedShares(cs, prevCommittee.size, s._2, Some(violatorPubKey))
      privKeyOpt match {
        case Success(privKey) =>
          val encryptedRandomness = randomnessSubmission.find(_._1 == violatorInfo.signingKey).get._2
          recoveredRandomness +:= RandomnessGenManager.decryptRandomnessShare(TreasuryManager.cs, privKey, encryptedRandomness).randomness
        case Failure(e) => log.error("Failed key recovery", e)
      }
    }
  }

  private def updateRandomness(): Unit = {
    val randBytes = (decryptedRandomness.values ++ recoveredRandomness).foldLeft(Array[Byte]()) { (acc, r) =>
      Bytes.concat(acc, r.getEncoded(true))
    }
    if (randBytes.nonEmpty)
      randomness = Blake2b256(randBytes)
    else log.error("No Randomness is detected! The constant salt will be used")
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

  private def retrieveSharedPublicKey(): Try[Unit] = Try {
      log.info("Computing shared public key")

      if (getApprovedCommitteeInfo.nonEmpty) {

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
          case Success(sharedPubKeyEncoded) =>
            val sharedPubKey = cs.decodePoint(sharedPubKeyEncoded)
            if (!sharedPubKey.equals(cs.infinityPoint)){
              sharedPublicKey = Some(sharedPubKey)
              log.info(s"Shared public key is: ${Base58.encode(sharedPublicKey.get.getEncoded(true))}")
            }
          case Failure(e) => log.error(e.getMessage)
        }
      } else log.warn("No committee members found!")
  }

  private def retrieveDisqualifiedAfterDKG(): Unit = {
    if (sharedPublicKey.isDefined) {
      val proxyKeys = getApprovedCommitteeInfo.map(_.proxyKey)
      val identifier = new SimpleIdentifier(proxyKeys)

      val disqualifiedOnR1 = DistrKeyGen.getDisqualifiedOnR1CommitteeMembersIDs(
        TreasuryManager.cs, proxyKeys, identifier, getDKGr1Data.values.toSeq, getDKGr2Data.values.toSeq)
      val disqualifiedOnR3 = DistrKeyGen.getDisqualifiedOnR3CommitteeMembersIDs(
        TreasuryManager.cs, proxyKeys, identifier, disqualifiedOnR1, getDKGr3Data.values.toSeq, getDKGr4Data.values.toSeq)

      val disqualifiedOnR1PubKeys = disqualifiedOnR1.map(identifier.getPubKey(_).get)
      val disqualifiedOnR3PubKeys = disqualifiedOnR3.map(identifier.getPubKey(_).get)

      val disqualifiedPubKeys = disqualifiedOnR1PubKeys ++ disqualifiedOnR3PubKeys
      disqualifiedCommitteeMembersAfterDKG ++= disqualifiedPubKeys.map(k => getApprovedCommitteeInfo.find(_.proxyKey == k).get)

      recoveredKeysOfDisqualifiedCommitteeMembers ++= DistrKeyGen.recoverKeysOfDisqualifiedOnR3Members(TreasuryManager.cs, proxyKeys.size,
        getDKGr5Data.values.toSeq, disqualifiedOnR1, disqualifiedOnR3)

      committeeInfo = committeeInfo.map(c => c.copy(participated = !disqualifiedOnR1PubKeys.contains(c.proxyKey)))
    }
  }

  private def updateDisqualifiedAfterDecryptionR1(): Unit = {
    /* First check that there was ballots that should be decrypted */
    if ((getExpertsBallots.nonEmpty || getVotersBallots.nonEmpty) && getSharedPubKey.isDefined) {
      /* Disqualified are those who didn't submit valid c1Share and hasn't been disqualified before */
      val disqualified = getApprovedCommitteeInfo
        .filter(i => !getDecryptionSharesR1.contains(getApprovedCommitteeInfo.indexOf(i)))
        .filter(i => !getDisqualifiedAfterDKGCommitteeInfo.exists(_.signingKey == i.signingKey))

      disqualifiedCommitteeMembersAfterDecryptionR1 = disqualified
    }
  }

  private def retrieveKeysOfDisqualified(recoveryShares: Map[Int, Seq[OpenedShare]]): Unit = {
    var recoveredKeys: Seq[(PubKey, PrivKey)] = Seq()
    recoveryShares.foreach { s =>
      val pubKey = cs.decodePoint(getDKGr3Data(s._1).commitments(0))
      val privKeyOpt = DistrKeyGen.recoverPrivateKeyByOpenedShares(cs, getApprovedCommitteeInfo.size, s._2, Some(pubKey))
      privKeyOpt match {
        case Success(privKey) => recoveredKeys +:= (pubKey, privKey)
        case Failure(e) => log.error("Failed key recovery", e)
      }
    }
    recoveredKeysOfDisqualifiedCommitteeMembers ++= recoveredKeys
  }

  private def updateDisqualifiedAfterDecryptionR2(): Unit = {
    /* First check that there was ballots that should be decrypted */
    if ((getExpertsBallots.nonEmpty || getVotersBallots.nonEmpty) && getSharedPubKey.isDefined && getDelegations.isDefined) {
      /* Disqualified are those who didn't submit valid c1Share and hasn't been disqualified before */
      val disqualified = getApprovedCommitteeInfo
        .filter(i => !getDecryptionSharesR2.contains(getApprovedCommitteeInfo.indexOf(i)))
        .filter(i => !getDisqualifiedAfterDKGCommitteeInfo.exists(_.signingKey == i.signingKey))
        .filter(i => !getDisqualifiedAfterDecryptionR1CommitteeInfo.exists(_.signingKey == i.signingKey))

      disqualifiedCommitteeMembersAfterDecryptionR2 = disqualified
    }
  }

  private def calculateDelegations(): Try[Unit] = Try {
    val deleg = proposals.indices.map { i =>
      val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))

      /* We can calculate delegations ONLY IF we have valid decryption shares from ALL committee members */
      val c1OfActiveCMs = getDecryptionSharesR1ForProposal(i).map(_.decryptedC1.map(_._1))
      val c1OfRecoveredCMs = decryptor.recoverDelegationsC1(recoveredKeysOfDisqualifiedCommitteeMembers.map(_._2))
      val allC1ForDelegations = c1OfActiveCMs ++ c1OfRecoveredCMs
      assert(allC1ForDelegations.size == getParticipatedCommitteeInfo.size)

      (i -> decryptor.computeDelegations(allC1ForDelegations))
    }
    delegations = Some(deleg.toMap)
  }

  private def calculateTallyResult(): Try[Unit] = Try {
    if (getDelegations.isDefined) {
      val result = proposals.indices.foreach { i =>
        val decryptor = new DecryptionManager(TreasuryManager.cs, getBallotsForProposal(i))
        val delegations = getDelegations.get(i)

        val c1OfActiveMembers = getDecryptionSharesR2ForProposal(i).map(_.decryptedC1.map(_._1))
        val c1OfRecoveredCMs = decryptor.recoverChoicesC1(recoveredKeysOfDisqualifiedCommitteeMembers.map(_._2), delegations)
        val allChoicesC1 = c1OfActiveMembers ++ c1OfRecoveredCMs

        /* We can decrypt final voting result ONLY IF we have valid decryption shares from ALL committee members */
        assert(allChoicesC1.size == getParticipatedCommitteeInfo.size)
        assert(delegations.size == getExpertsInfo.size)

        val tally = decryptor.computeTally(allChoicesC1, delegations)
        if (tally.isSuccess)
          tallyResult = tallyResult + (i -> tally.get)
      }
    }
  }

  def getPunishedParties: Try[Seq[PartyInfo]] = Try {
    val disqualifiedCommittee = getAllDisqualifiedCommitteeInfo
    val absentDuringRandGenCommittee = getApprovedCommitteeInfo.indices
      .filter(i => !getSubmittedRandomnessForNextEpoch.contains(i))
      .map(i => getApprovedCommitteeInfo(i))
      .filter(ci => !disqualifiedCommittee.exists(_.depositBox == ci.depositBox))

    /* Experts should be punished only if they were supposed to vote but didn't do this.
    *  If, for inctance, an expert didn't vote because of failed Distributed Key Generation,
    *  then he should not be punished */
    val absentExperts =
      if (sharedPublicKey.isDefined)
        getExpertsInfo.indices.filter(i => !getExpertsBallots.contains(i)).map(i => getExpertsInfo(i))
      else Seq()

    disqualifiedCommittee ++ absentDuringRandGenCommittee ++ absentExperts
  }

  def getPenalties: Seq[PublicKey25519NoncedBox] = getPunishedParties match {
    case Success(p) => p.map(_.depositBox)
    case Failure(e) =>
      log.error("Cant retrieve punished parties", e)
      Seq()
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

    /* If a valid rand submission from a committee is existed, it means that he has also successfully accomplished
     * all previous stages and hasn't been disqualified */
    val payedCommittee = getSubmittedRandomnessForNextEpoch.map(v => getApprovedCommitteeInfo(v._1).paybackAddr)
    if (payedCommittee.size > 0) {
      val paymentPerCommittee = Value @@ (TreasuryManager.COMMITTEE_BUDGET / payedCommittee.size).round
      if (paymentPerCommittee > 0)
        payments = payments ++ payedCommittee.map(v => (v, paymentPerCommittee))
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
    // we should take all registration blocks and first block after registration (cause at this point approved CMs are selected)
    val epochBlocksIds = history.lastBlockIds(history.bestBlock, count).take(TreasuryManager.EXPERT_REGISTER_RANGE.end + 1)

    val trState = TreasuryState(epochId)

    /* reconstruct necessary part of the TreasuryState */
    epochBlocksIds.foreach(blockId => trState.apply(history.modifierById(blockId).get, history).get)

    (trState.getVotersInfo, trState.getExpertsInfo, trState.getCommitteeInfo)
  }

  /**
    * Recovers info about R1Data submissions for old epochs.
    * It is done by parsing R1Data blocks for the required epoch.
    *
    * @param history history
    * @param epochId epochid
    * @return Success(seq) where seq is a sequence of R1Data
    */
  def generateR1Data(history: HybridHistory, epochId: Int): Try[Seq[R1Data]] = Try {
    val currentHeight = history.storage.height.toInt
    val currentEpochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN
    require(epochId >= 0 && epochId < currentEpochNum, "R1Data can be generated only for past epochs. Use getR1Data methods directly for the current epoch.")

    val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
    // we should take all R1Data blocks
    val epochBlocksIds = history.lastBlockIds(history.bestBlock, count)
      .take(TreasuryManager.DISTR_KEY_GEN_R1_RANGE.end)
      .drop(TreasuryManager.DISTR_KEY_GEN_R1_RANGE.start)

    /* extract R1Data */
    var r1Data: Seq[R1Data] = Seq()
    epochBlocksIds.foreach { blockId =>
      history.modifierById(blockId).get.transactions.collect {case t: DKGr1Transaction => t}.foreach { t =>
        r1Data :+= t.r1Data
      }
    }
    r1Data
  }

  /**
    * Recovers info about R3Data submissions for old epochs.
    * It is done by parsing R3Data blocks for the required epoch.
    *
    * @param history history
    * @param epochId epochid
    * @return Success(seq) where seq is a sequence of R3Data
    */
  def generateR3Data(history: HybridHistory, epochId: Int): Try[Seq[R3Data]] = Try {
    val currentHeight = history.storage.height.toInt
    val currentEpochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN
    require(epochId >= 0 && epochId < currentEpochNum, "R3Data can be generated only for past epochs. Use getR3Data methods directly for the current epoch.")

    val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
    // we should take all R3Data blocks
    val epochBlocksIds = history.lastBlockIds(history.bestBlock, count)
      .take(TreasuryManager.DISTR_KEY_GEN_R3_RANGE.end)
      .drop(TreasuryManager.DISTR_KEY_GEN_R3_RANGE.start)

    /* extract R3Data */
    var r3Data: Seq[R3Data] = Seq()
    epochBlocksIds.foreach { blockId =>
      history.modifierById(blockId).get.transactions.collect {case t: DKGr3Transaction => t}.foreach { t =>
        r3Data :+= t.r3Data
      }
    }
    r3Data
  }

  /**
    * Recovers info about randomness submissions for old epochs.
    * It is done by parsing randomness submission blocks for the required epoch.
    *
    * @param history history
    * @param epochId epochid
    * @return Success(seq) where seq is a sequence of encrypted randomness paired with a signing public key
    *         of the committee member who submitted this randomness
    */
  def generateRandomnessSubmission(history: HybridHistory, epochId: Int):
    Try[Seq[(PublicKey25519Proposition, Ciphertext)]] = Try {

    val currentHeight = history.storage.height.toInt
    val currentEpochNum = currentHeight / TreasuryManager.EPOCH_LEN
    val currentEpochHeight = currentHeight % TreasuryManager.EPOCH_LEN
    require(epochId >= 0 && epochId < currentEpochNum, "Randomness submission can be generated only for past epochs. Use getSubmittedRandomness method directly for the current epoch.")

    val count = (currentEpochNum - epochId) * TreasuryManager.EPOCH_LEN + currentEpochHeight + 1
    // we should take all randomness submission blocks
    val epochBlocksIds = history.lastBlockIds(history.bestBlock, count)
      .take(TreasuryManager.RANDOMNESS_SUBMISSION_RANGE.end)
      .drop(TreasuryManager.RANDOMNESS_SUBMISSION_RANGE.start)

    /* extract Randomness data */
    var submittedRandomness: Seq[(PublicKey25519Proposition, Ciphertext)] = Seq()
    epochBlocksIds.foreach { blockId =>
      history.modifierById(blockId).get.transactions.collect {case t: RandomnessTransaction => t}.foreach { t =>
        submittedRandomness :+= (t.pubKey, t.encryptedRandomness)
      }
    }
    submittedRandomness
  }

  /**
    * Generate TreasuryState for an epoch to which `endBlock` belongs. Note that `state` is optional because
    * it is needed only to validate PaymentTransaction. In cases when it is not needed state can be None.
    *
    * @param history history
    * @param endBlock the id of the block in the history until which an epoch should be reconstructed
    * @param state minimal state
    * @return
    */
  def generate(history: HybridHistory, endBlock: ModifierId, state: Option[HBoxStoredState] = None): Try[TreasuryState] = Try {
    CommitteeMember.stopMember()
    println("Generating current treasury state ...")

    val height = history.storage.heightOf(endBlock).get.toInt
    val epochNum = height / TreasuryManager.EPOCH_LEN
    val epochHeight = height % TreasuryManager.EPOCH_LEN

    val epochBlocksIds = history.lastBlockIds(history.modifierById(endBlock).get, epochHeight + 1)

    val trState = TreasuryState(epochNum)

    val strings = epochBlocksIds.map(Base58.encode(_) + "\n")
    println(s"Applying blocks for endBlock: ${Base58.encode(endBlock)} \n ${strings}")
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
                         participated: Boolean, // true only if a CM successfully passed the Round 1 of DKG and submitted its share
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