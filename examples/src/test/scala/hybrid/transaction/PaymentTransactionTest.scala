package hybrid.transaction

import examples.commons.{SimpleBoxTransactionCompanion, Value}
import examples.hybrid.transaction.PaymentTransaction
import hybrid.HybridGenerators
import org.scalatest.FunSuite
import scorex.core.transaction.box.proposition.PublicKey25519Proposition

class PaymentTransactionTest extends FunSuite with HybridGenerators {

  test("serialization") {
    val to: IndexedSeq[(PublicKey25519Proposition, Value)] = IndexedSeq(
      (propositionGen.sample.get, Value @@ 10L),
      (propositionGen.sample.get, Value @@ 20L),
      (propositionGen.sample.get, Value @@ 30L),
    )

    val tx = PaymentTransaction(0, to, 123L)

    val parsed = SimpleBoxTransactionCompanion.parseBytes(tx.bytes).get.asInstanceOf[PaymentTransaction]

    assert(tx.bytes sameElements parsed.bytes)

    assert(parsed.timestamp == 123L)
    assert(parsed.epochID == 0)
    assert(parsed.to.size == 3)
    to.zip(parsed.to).foreach { case (a1, a2) =>
      assert(a1._1.equals(a2._1))
      assert(a1._2 == a2._2)
    }
  }
}
