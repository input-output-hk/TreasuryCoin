package hybrid.transaction

import com.google.common.primitives.Longs
import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.transaction.DKGr1Transaction
import org.scalatest.FunSuite
import scorex.core.transaction.state.PrivateKey25519Companion
import treasury.crypto.core.Cryptosystem
import treasury.crypto.keygen.CommitteeMember

class DKGTransactionsTest extends FunSuite {

  test("tx_serialization") {

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    val epochID = 123
    val (privateKey, _) = PrivateKey25519Companion.generateKeys(Longs.toByteArray(scala.util.Random.nextLong()))

//    val r1Tx1Bytes = DKGr1Transaction.create(privateKey, r1Data(0), epochID).get.bytes
//    val r1Tx = SimpleBoxTransactionCompanion.parseBytes(r1Tx1Bytes).get.asInstanceOf[DKGr1Transaction]

    val r1TxBytes = r1Data.map(r1d => DKGr1Transaction.create(privateKey, r1d, epochID).get.bytes)

    val r1DataRestored = r1TxBytes.map(
      r1b => {
        val r1Tx = SimpleBoxTransactionCompanion.parseBytes(r1b).get.asInstanceOf[DKGr1Transaction]

        assert(r1Tx.semanticValidity.isSuccess)
        assert(r1Tx.epochID == epochID)

        r1Tx.r1Data
      }
    )

    assert(r1DataRestored.equals(r1Data))

    val r2Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR2(r1DataRestored)
    }

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    val r5_2Data = for (i <- committeeMembersPubKeys.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(cs.decodePoint)

    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}

    assert(publicKeysSum.equals(sharedPublicKeys(0)))

  }
}
