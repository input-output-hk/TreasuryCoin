package hybrid.transaction

import com.google.common.primitives.Longs
import examples.commons.SimpleBoxTransactionCompanion
import examples.hybrid.transaction.DKG._
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

    val r2TxBytes = r2Data.map(r2d => DKGr2Transaction.create(privateKey, r2d, epochID).get.bytes)
    val r2DataRestored = r2TxBytes.map(
      r2b => {
        val r2Tx = SimpleBoxTransactionCompanion.parseBytes(r2b).get.asInstanceOf[DKGr2Transaction]

        assert(r2Tx.semanticValidity.isSuccess)
        assert(r2Tx.epochID == epochID)

        r2Tx.r2Data
      }
    )
    assert(r2DataRestored.equals(r2Data))

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    val r3TxBytes = r3Data.map(r3d => DKGr3Transaction.create(privateKey, r3d, epochID).get.bytes)
    val r3DataRestored = r3TxBytes.map(
      r3b => {
        val r3Tx = SimpleBoxTransactionCompanion.parseBytes(r3b).get.asInstanceOf[DKGr3Transaction]

        assert(r3Tx.semanticValidity.isSuccess)
        assert(r3Tx.epochID == epochID)

        r3Tx.r3Data
      }
    )
    assert(r3DataRestored.equals(r3Data))

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    val r4TxBytes = r4Data.map(r4d => DKGr4Transaction.create(privateKey, r4d, epochID).get.bytes)
    val r4DataRestored = r4TxBytes.map(
      r4b => {
        val r4Tx = SimpleBoxTransactionCompanion.parseBytes(r4b).get.asInstanceOf[DKGr4Transaction]

        assert(r4Tx.semanticValidity.isSuccess)
        assert(r4Tx.epochID == epochID)

        r4Tx.r4Data
      }
    )
    assert(r4DataRestored.equals(r4Data))

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    val r5_1TxBytes = r5_1Data.map(r5d => DKGr5Transaction.create(privateKey, r5d, epochID).get.bytes)
    val r5_1DataRestored = r5_1TxBytes.map(
      r5b => {
        val r5Tx = SimpleBoxTransactionCompanion.parseBytes(r5b).get.asInstanceOf[DKGr5Transaction]

        assert(r5Tx.semanticValidity.isSuccess)
        assert(r5Tx.epochID == epochID)

        r5Tx.r5_1Data
      }
    )
    assert(r5_1DataRestored.equals(r5_1Data))

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
