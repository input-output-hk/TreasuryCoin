package examples.hybrid.api.http

import java.math.BigInteger

import akka.actor.{ActorRef, ActorRefFactory}
import akka.http.scaladsl.server.Route
import examples.commons.{SimpleBoxTransactionMemPool, Value}
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.{HBoxStoredState, Proposal, TreasuryState, TreasuryTxValidator}
import examples.hybrid.transaction.{BallotTransaction, ProposalTransaction, TreasuryTransaction}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.wallet.HWallet
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax._
import scorex.core.NodeViewHolder.ReceivableMessages.LocallyGeneratedTransaction
import scorex.core.api.http.{ApiException, ApiRouteWithFullView, SuccessApiResponse}
import scorex.core.settings.RESTApiSettings
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.crypto.encode.Base58
import treasury.crypto.core.{One, VoteCases}
import treasury.crypto.voting.ballots.Ballot
import treasury.crypto.voting.{Expert, RegularVoter, Voter}

import scala.concurrent.Await
import scala.util.{Failure, Success, Try}


case class TreasuryApiRoute(override val settings: RESTApiSettings, nodeViewHolderRef: ActorRef)
                           (implicit val context: ActorRefFactory)
  extends ApiRouteWithFullView[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool] {

  override val route = pathPrefix("treasury") {
    infoRoute ~ epochIdInfoRoute ~ ballotCast ~ proposalCast
  }

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]
  type VoteValue = Either[Int, VoteCases.Value]

  private def getCurrentView: Try[NodeView] = Try {
    def f(view: NodeView): NodeView = view

    import akka.pattern.ask
    import scala.concurrent.duration._

    Await.result(nodeViewHolderRef ? GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      NodeView](f), 5.seconds).asInstanceOf[NodeView]
  }

  def getTreasuryInfo(state: TreasuryState): Json = {
    Map(
      "epoch"                 -> state.epochNum.asJson,
      "committeeKeys"         -> state.getCommitteeInfo.map(c => s"Signing key: ${c.signingKey}, proxy key: ${Base58.encode(c.proxyKey.getEncoded(true))}").asJson,
      "approvedCommitteeKeys" -> state.getApprovedCommitteeInfo.map(c => s"Signing key: ${c.signingKey}, proxy key: ${Base58.encode(c.proxyKey.getEncoded(true))}").asJson,
      "expertsSigningKeys"    -> state.getExpertsInfo.map(_.signingKey).map(pk => pk.toString).asJson,
      "votersSigningKeys"     -> state.getVotersInfo.map(_.signingKey).map(pk => pk.toString).asJson,
      "sharedPubKey"          -> state.getSharedPubKey.map(_.getEncoded(true)).map(Base58.encode).getOrElse("None").asJson,
      "votersBallots"         -> state.getVotersBallots.map(voter => (s"Voter id: ${voter._1} submitted")).asJson,
      "expertsBallots"        -> state.getExpertsBallots.map(expert => (s"Expert id ${expert._1} submitted")).asJson,
      "proposals"             -> state.getProposals.map(p => Map(s"${state.getProposals.indexOf(p)} ${p.name}" -> s"${p.requestedSum} -> ${p.recipient}")).asJson,
      "R1Data"                -> state.getDKGr1Data.map(m => s"Committee id ${m._1} submitted").asJson,
      "R2Data"                -> state.getDKGr2Data.map(m => s"Committee id ${m._1} submitted").asJson,
      "R3Data"                -> state.getDKGr3Data.map(m => s"Committee id ${m._1} submitted").asJson,
      "R4Data"                -> state.getDKGr4Data.map(m => s"Committee id ${m._1} submitted").asJson,
      "R5Data"                -> state.getDKGr5Data.map(m => s"Committee id ${m._1} submitted").asJson,
      "disqualifiedCommitteeMembers"  -> state.getAllDisqualifiedCommitteeInfo.map(_.signingKey.toString).asJson,
      "disqualifiedAfterDKG"  -> state.getDisqualifiedAfterDKGCommitteeInfo.map(_.signingKey.toString).asJson,
      "disqualifiedAfterDecryptionR1" -> state.getDisqualifiedAfterDecryptionR1CommitteeInfo.map(_.signingKey.toString).asJson,
      "disqualifiedAfterDecryptionR2" -> state.getDisqualifiedAfterDecryptionR2CommitteeInfo.map(_.signingKey.toString).asJson,
      "disqualifiedAfterRandGen" -> state.getDisqualifiedAfterRandGenCommitteeInfo.map(_.signingKey.toString).asJson,
      "recoveredKeys"         -> state.getRecoveredKeys.map(_._1.toString).asJson,
      "decryption shares R1"  -> state.getDecryptionSharesR1.map(member => s"Committee id ${member._1}. Number of submitted shares: ${member._2.size}").asJson,
      "recovery shares R1"    -> state.getKeyRecoverySharesR1.map(m => s"Recovered committee id ${m._1}. Submitters ids: ${m._2.map(_.receiverID.toString)}").asJson,
      "decryption shares R2"  -> state.getDecryptionSharesR2.map(member => s"Committee id ${member._1}. Number of submitted shares: ${member._2.size}").asJson,
      "recovery shares R2"    -> state.getKeyRecoverySharesR2.map(m => s"Recovered committee id ${m._1}. Submitters ids: ${m._2.map(_.receiverID.toString)}").asJson,
      "voting result"         -> state.getTally.map(p => s"Proposal ${p._1}: {yes: ${p._2.yes}, no: ${p._2.no}, abstain ${p._2.abstain}}").asJson,
      "penalties"             -> state.getPunishedParties.map(_.map(p => s"Party signing key: ${p.signingKey}, value: ${p.depositBox.value}").asJson).getOrElse("Error while retrieving punished parties".asJson),
      "coinbase payments"     -> state.getPayments.getOrElse(Seq()).map(p => s"Address: ${p._1.address}, value: ${p._2}").asJson,
      "randomness submission" -> state.getSubmittedRandomnessForNextEpoch.map(r => s"Committee id ${r._1} submitted").asJson,
      "randomness decryption" -> state.getDecryptedRandomness.map(r => s"Committee id ${r._1} submitted").asJson,
      "randomness recovery shares"    -> state.getKeyRecoverySharesRandGen.map(m => s"Recovered committee id ${m._1}. Submitters ids: ${m._2.map(_.receiverID.toString)}").asJson,
      "randomness recovered"  -> state.getRecoveredRandomness.map(r => "111111").asJson,
      "randomness"            -> Base58.encode(state.getRandomness).asJson
    ).asJson
  }

  def epochIdInfoRoute: Route = path("info" / IntNumber) { epochId =>
      val trState = TreasuryState.generate(getCurrentView.get.history, epochId)
      getJsonRoute {
        trState match {
          case Success(s) => SuccessApiResponse(getTreasuryInfo(s))
          case Failure(e) => ApiException(e)
        }
      }
  }

  def infoRoute: Route = path("info") {
    val trState = getCurrentView.get.trState
    getJsonRoute {
      SuccessApiResponse(getTreasuryInfo(trState))
    }
  }

  private def createBallotTx (
    proposalsVotes: Map[Int, VoteValue],
    view: NodeView,
  ): Option[BallotTransaction] = {

    val vault = view.vault
    val state = view.trState

    def getKeyFor(role: Role.Role): Option[PublicKey25519Proposition] = {

      val keys = vault.treasurySigningPubKeys(role, state.epochNum)

      keys.headOption match {
        case Some(key) if state.getSigningKeys(role).contains(key) => Some(key)
        case _ => None
      }
    }

    def createBallot (
      proposal:       Proposal,
      voter:          Voter,
      proposalsVotes: Map[Int, VoteValue]
    ): Option[Ballot] = {

      val proposalId = state.getProposals.indexOf(proposal)
      val voteOpt = proposalsVotes.get(proposalId)

      if (voteOpt.isDefined) {

        voter match {
          case v: RegularVoter =>
            voteOpt.get match {
              case Right(vote) => Some(v.produceVote(proposalId, vote))
              case Left(delegateId) => Some(v.produceDelegatedVote(proposalId, delegateId))
            }
          case e: Expert =>
            voteOpt.get match {
              case Right(vote) => Some(e.produceVote(proposalId, vote))
              case _ => None
            }
          case _ => None
        }
      }
      else
        None
    }

    def createTx (ballots:   Seq[Ballot],
                  expertKey: Option[PublicKey25519Proposition],
                  voterKey:  Option[PublicKey25519Proposition]
    ): Option[BallotTransaction] = {

      // TODO: transaction should be signed both with expert and regular voter keys, if both of them have been used during the ballots casting

      def getBallotTx (voterKey: Option[PublicKey25519Proposition],
                       voterType: VoterType.VoterType
      ): Try[BallotTransaction] = {

        voterKey match {
          case Some(key) =>
            val signingSecret = vault.treasurySigningSecretByPubKey(state.epochNum, key)
            if (signingSecret.isDefined) {
              val privKey = signingSecret.get.privKey
              BallotTransaction.create(privKey, voterType, ballots, state.epochNum)
            } else {
              Failure(new Exception("Signing secret is absent"))
            }
          case _ => Failure(new Exception("Key is absent"))
        }
      }

      def isValidBallotTx(txToValidate: BallotTransaction): Boolean = {

        val pending = view.pool.unconfirmed.values.exists {
          case tx: BallotTransaction => tx.pubKey == txToValidate.pubKey
          case _ => false
        }
        val isValid = Try(new TreasuryTxValidator(state, view.history.height)).flatMap(_.validate(txToValidate)).isSuccess
        !pending && isValid
      }

      // Temporary protection while the model with a common role for all proposals is used.
      // Here a transaction is issued only with an expert or regular voter signature.
      val ballotTx =
        if (expertKey.isDefined)
          getBallotTx(expertKey, VoterType.Expert)
        else if(voterKey.isDefined)
          getBallotTx(voterKey,  VoterType.Voter)
      else
          Failure(new Exception("Voter keys are undefined"))

      ballotTx match {
        case Success(tx: BallotTransaction) if isValidBallotTx(tx) => Some(tx)
        case _ => None
      }
    }

    if (state.getSharedPubKey.isDefined) {

      val sharedPubKey = state.getSharedPubKey.get

      val myExpertKey = getKeyFor(Role.Expert)

      // Temporary protection while the model with a common role for all proposals is used.
      // Here if user is an expert, there is no need for him to cast regular voter's ballots.
      val myVoterKey = if (myExpertKey.isEmpty) getKeyFor(Role.Voter) else None

      val ballots = state.getProposals.map {

        proposal =>

          // TODO: add a check for the role of a voter relatively to the current proposal
          // if(IsExpert(myExpertKey, proposal)) {
          if (myExpertKey.isDefined) {

            val expertId = state.getExpertsInfo.map(_.signingKey).indexOf(myExpertKey.get)
            val expert = Expert(TreasuryManager.cs, expertId, sharedPubKey)
            createBallot(proposal, expert, proposalsVotes)

          // } else {
          } else if (myVoterKey.isDefined) {

            val numOfExperts = state.getExpertsInfo.size
            val stake = state.getVotersInfo.find(_.signingKey == myVoterKey.get).get.depositBox.value
            val voter = new RegularVoter(TreasuryManager.cs, numOfExperts, sharedPubKey, BigInteger.valueOf(stake))
            createBallot(proposal, voter, proposalsVotes)
          }
          else
            None

      }.collect {case Some(ballot) => ballot}

      createTx(ballots, myExpertKey, myVoterKey)
    }
    else
      None
  }

  // Ballot parameters example (proposalId : voteCase or delegateID)
  //{
  //  "0": "Yes",
  //  "1": "No",
  //  "2": "0"
  //}

  def ballotCast: Route = path("ballot") {
    post{
      entity(as[String]) { body =>
        withAuth {
          postJsonRoute {
            parse(body) match {
              case Left(failure) => ApiException(failure.getCause)
              case Right(json) => Try {

                import io.circe._, io.circe.syntax._

                implicit val decodeIntOrString: Decoder[Either[Int, String]] =
                  Decoder[Int].map(Left(_)).or(Decoder[String].map(Right(_)))

                val Right(proposals) = json.as[Map[Int, Either[Int, String]]]

                val proposalsVotes = proposals.map {
                  p =>
                    p._1 -> (p._2 match {
                      case Right(s) => s match {
                        case "Yes" => Right(VoteCases.Yes)
                        case "No"  => Right(VoteCases.No)
                        case _     => Right(VoteCases.Abstain)
                      }
                      case Left(i) => Left(i)
                    })
                }

                val ballotTx = createBallotTx(proposalsVotes, getCurrentView.get)

                val success = ballotTx match {
                  case Some(tx) => nodeViewHolderRef ! LocallyGeneratedTransaction[PublicKey25519Proposition, TreasuryTransaction](tx); true
                  case None => false
                }

                Map("status" -> (if(success) "ok" else "err")).asJson

              } match {
                case Success(resp) => SuccessApiResponse(resp)
                case Failure(e) => ApiException(e)
              }
            }
          }
        }
      }
    }
  }

  private def createProposalTx (
                               proposal: (String, Int),
                               view: NodeView,
                             ): Option[ProposalTransaction] = {

    def isValidProposalTx(txToValidate: ProposalTransaction): Boolean = {

      val pending = view.pool.unconfirmed.values.exists {
        case tx: ProposalTransaction => tx.name == txToValidate.name
        case _ => false
      }
      val isValid = Try(new TreasuryTxValidator(view.trState, view.history.height)).flatMap(_.validate(txToValidate)).isSuccess
      !pending && isValid
    }

    val submittedProposals = view.trState.getProposals

    // proposal with the specified name hasn't been submitted yet
    if(!submittedProposals.exists(_.name == proposal)) {
      val wallet = view.vault
      val pubkey = wallet.publicKeys.toSeq.headOption.get
      ProposalTransaction.create(wallet, s"${proposal._1}", Value @@ proposal._2.toLong, pubkey, view.trState.epochNum) match {
        case Success(tx: ProposalTransaction) if isValidProposalTx(tx) => Some(tx)
        case _ => None
      }
    } else None
  }

  def proposalCast: Route = path("proposal") {
    post{
      entity(as[String]) { body =>
        withAuth {
          postJsonRoute {
            parse(body) match {
              case Left(failure) => ApiException(failure.getCause)
              case Right(json) => Try {

                val view = getCurrentView.get

                json.as[Map[String, Int]] match {
                  case Right(proposals) =>
                    proposals.map {
                      p => {
                        p._1 -> {
                          createProposalTx(p, view) match {
                            case Some(tx) => nodeViewHolderRef ! LocallyGeneratedTransaction[PublicKey25519Proposition, TreasuryTransaction](tx); "submitted"
                            case None => "rejected"
                          }
                        }
                      }
                    }.asJson

                  case Left(decodingErr) =>
                    Map("status" -> decodingErr.message).asJson
                }
              } match {
                case Success(resp) => SuccessApiResponse(resp)
                case Failure(e) => ApiException(e)
              }
            }
          }
        }
      }
    }
  }
}