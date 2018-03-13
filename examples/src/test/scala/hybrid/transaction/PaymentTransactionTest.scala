package hybrid.transaction

import examples.commons.{PublicKey25519NoncedBox, SimpleBoxTransactionCompanion, Value}
import examples.hybrid.transaction.PaymentTransaction
import hybrid.HybridGenerators
import org.scalatest.FunSuite
import scorex.core.transaction.box.proposition.PublicKey25519Proposition

class PaymentTransactionTest extends FunSuite with HybridGenerators {

  test("serialization") {
    val coinbasePayments: IndexedSeq[(PublicKey25519Proposition, Value)] = IndexedSeq(
      (propositionGen.sample.get, Value @@ 10L),
      (propositionGen.sample.get, Value @@ 20L),
      (propositionGen.sample.get, Value @@ 30L),
    )

    val depositPaybacks: IndexedSeq[(PublicKey25519NoncedBox, PublicKey25519Proposition)] = IndexedSeq(
      (noncedBoxGen.sample.get, propositionGen.sample.get),
      (noncedBoxGen.sample.get, propositionGen.sample.get),
      (noncedBoxGen.sample.get, propositionGen.sample.get)
    )

    val tx = PaymentTransaction(depositPaybacks, coinbasePayments, 0, 123L)

    val parsed = SimpleBoxTransactionCompanion.parseBytes(tx.bytes).get.asInstanceOf[PaymentTransaction]

    assert(tx.bytes sameElements parsed.bytes)

    assert(parsed.timestamp == 123L)
    assert(parsed.epochID == 0)
    assert(parsed.coinbasePayments.size == 3)
    assert(parsed.depositPayback.size == 3)
    coinbasePayments.zip(parsed.coinbasePayments).foreach { case (a1, a2) =>
      assert(a1._1.equals(a2._1))
      assert(a1._2 == a2._2)
    }
    depositPaybacks.zip(parsed.depositPayback).foreach { case (a1, a2) =>
      assert(a1._1.equals(a2._1))
      assert(a1._2.equals(a2._2))
    }
  }
}
