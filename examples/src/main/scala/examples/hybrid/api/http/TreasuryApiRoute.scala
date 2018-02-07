package examples.hybrid.api.http

import akka.actor.{ActorRef, ActorRefFactory}
import akka.http.scaladsl.server.Route
import examples.commons.SimpleBoxTransactionMemPool
import examples.hybrid.HybridNodeViewHolder.{CurrentViewWithTreasuryState, GetDataFromCurrentViewWithTreasuryState}
import examples.hybrid.TreasuryManager
import examples.hybrid.TreasuryManager.Role
import examples.hybrid.history.HybridHistory
import examples.hybrid.state.{HBoxStoredState, Proposal, TreasuryTxValidator}
import examples.hybrid.transaction.{BallotTransaction, TreasuryTransaction}
import examples.hybrid.transaction.BallotTransaction.VoterType
import examples.hybrid.wallet.HWallet
import io.circe.parser.parse
import io.circe.syntax._
import scorex.core.LocalInterface.LocallyGeneratedTransaction
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
    infoRoute ~ ballotCast
  }

  type NodeView = CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]
  type VoteValue = Either[Int, VoteCases.Value]

  private def getCurrentView: Try[NodeView] = Try {
    def f(view: CurrentViewWithTreasuryState[HybridHistory, HBoxStoredState, HWallet, SimpleBoxTransactionMemPool]): NodeView = view

    import akka.pattern.ask
    import scala.concurrent.duration._

    Await.result(nodeViewHolderRef ? GetDataFromCurrentViewWithTreasuryState[HybridHistory,
      HBoxStoredState,
      HWallet,
      SimpleBoxTransactionMemPool,
      NodeView](f), 5.seconds).asInstanceOf[NodeView]
  }

  def infoRoute: Route = path("info") {

    val trState = getCurrentView.get.trState

    getJsonRoute {
      SuccessApiResponse(Map(
        "epoch"                 -> trState.epochNum.asJson,
        "committeeProxyKeys"    -> trState.getCommitteeProxyKeys.map(pk => Base58.encode(pk.getEncoded(true))).asJson,
        "committeeSigningKeys"  -> trState.getCommitteeSigningKeys.map(pk => pk.toString).asJson,
        "expertsSigningKeys"    -> trState.getExpertsSigningKeys.map(pk => pk.toString).asJson,
        "votersSigningKeys"     -> trState.getVotersSigningKeys.map(pk => pk.toString).asJson,
        "sharedPubKey"          -> Base58.encode(trState.getSharedPubKey.getOrElse(trState.cs.infinityPoint).getEncoded(true)).asJson,
        "votersBallots"         -> trState.getVotersBallots.map(voter => (voter._1, voter._2.map(ballot => Base58.encode(ballot.bytes)).asJson)).asJson,
        "expertsBallots"        -> trState.getExpertsBallots.map(expert => (expert._1, expert._2.map(ballot => Base58.encode(ballot.bytes)).asJson)).asJson,
        "proposals"             -> trState.getProposals.map(p => Map(s"${trState.getProposals.indexOf(p)} ${p.name}" -> s"${p.requestedSum} -> ${p.recipient}")).asJson
//        "proposals"         -> trState.getProposals.map(p => p.name -> s"${p.requestedSum} -> ${p.recipient}").toMap.asJson // merges equally named proposals
      ).asJson)
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

      if (keys.nonEmpty &&
          state.getSigningKeys(role).contains(keys.head))
        Some(keys.head)
      else
        None
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

      def IsValidBallotTx(txToValidate: BallotTransaction): Boolean = {

        val pending = view.pool.unconfirmed.values.exists {
          case tx: BallotTransaction => tx.pubKey == txToValidate.pubKey
          case _ => false
        }
        val isValid = new TreasuryTxValidator(state, view.history.height).validate(txToValidate).isSuccess
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
        case Success(tx: BallotTransaction) => if (IsValidBallotTx(tx)) Some(tx) else None
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

            val expertId = state.getExpertsSigningKeys.indexOf(myExpertKey.get)
            val expert = Expert(TreasuryManager.cs, expertId, sharedPubKey)
            createBallot(proposal, expert, proposalsVotes)

          // } else {
          } else if (myVoterKey.isDefined) {

            val numOfExperts = state.getExpertsSigningKeys.size
            val voter = new RegularVoter(TreasuryManager.cs, numOfExperts, sharedPubKey, One)
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
}