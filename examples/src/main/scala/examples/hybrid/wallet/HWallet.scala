package examples.hybrid.wallet

import java.io.File

import com.google.common.primitives.{Bytes, Ints, Longs}
import examples.commons.SimpleBoxTransaction
import examples.curvepos.transaction.{PublicKey25519NoncedBox, PublicKey25519NoncedBoxSerializer}
import examples.hybrid.TreasuryManager
import examples.hybrid.blocks.HybridBlock
import examples.hybrid.state.HBoxStoredState
import examples.hybrid.transaction.RegisterTransaction.Role
import examples.hybrid.transaction.RegisterTransaction.Role.Role
import io.iohk.iodb.{ByteArrayWrapper, LSMStore}
import scorex.core.VersionTag
import scorex.core.serialization.Serializer
import scorex.core.settings.ScorexSettings
import scorex.core.transaction.box.proposition.PublicKey25519Proposition
import scorex.core.transaction.state.{PrivateKey25519, PrivateKey25519Companion, PrivateKey25519Serializer}
import scorex.core.transaction.wallet.{Wallet, WalletBox, WalletBoxSerializer, WalletTransaction}
import scorex.core.utils.{ByteStr, ScorexLogging}
import scorex.crypto.encode.Base58
import scorex.crypto.hash.Blake2b256
import treasury.crypto.core.{PrivKey, PubKey}

import scala.annotation.tailrec
import scala.util.{Success, Failure, Try}


case class HWallet(seed: ByteStr, store: LSMStore)
  extends Wallet[PublicKey25519Proposition, SimpleBoxTransaction, HybridBlock, HWallet]
    with ScorexLogging {

  override type S = PrivateKey25519
  override type PI = PublicKey25519Proposition

  private val BoxIdsKey: ByteArrayWrapper = ByteArrayWrapper(Array.fill(store.keySize)(1: Byte))
  private val SecretsKey: ByteArrayWrapper = ByteArrayWrapper(Array.fill(store.keySize)(2: Byte))
  private val TreasurySecretsKey: ByteArrayWrapper = ByteArrayWrapper(Array.fill(store.keySize)(3: Byte))

  def boxIds: Seq[Array[Byte]] = {
    store.get(BoxIdsKey).map(_.data.grouped(store.keySize).toSeq).getOrElse(Seq[Array[Byte]]())
  }

  private lazy val walletBoxSerializer =
    new WalletBoxSerializer[PublicKey25519Proposition, PublicKey25519NoncedBox](PublicKey25519NoncedBoxSerializer)

  //intentionally not implemented for now
  override def historyTransactions: Seq[WalletTransaction[PublicKey25519Proposition, SimpleBoxTransaction]] = ???

  override def boxes(): Seq[WalletBox[PublicKey25519Proposition, PublicKey25519NoncedBox]] = {
    boxIds
      .flatMap(id => store.get(ByteArrayWrapper(id)))
      .map(_.data)
      .map(ba => walletBoxSerializer.parseBytes(ba))
      .map(_.get)
      .filter(_.box.value > 0)
  }

  override def publicKeys: Set[PublicKey25519Proposition] = secrets.map(_.publicImage)

  override def secrets: Set[PrivateKey25519] = store.get(SecretsKey)
    .map(_.data.grouped(64).map(b => PrivateKey25519Serializer.parseBytes(b).get).toSet)
    .getOrElse(Set.empty[PrivateKey25519])

  override def secretByPublicImage(publicImage: PublicKey25519Proposition): Option[PrivateKey25519] =
    secrets.find(s => s.publicImage == publicImage)

  override def generateNewSecret(): HWallet = {
    val prevSecrets = secrets
    val nonce: Array[Byte] = Ints.toByteArray(prevSecrets.size)
    val s = Blake2b256(seed.arr ++ nonce)
    val (priv, _) = PrivateKey25519Companion.generateKeys(s)
    val allSecrets: Set[PrivateKey25519] = Set(priv) ++ prevSecrets
    store.update(ByteArrayWrapper(priv.privKeyBytes),
      Seq(),
      Seq(SecretsKey -> ByteArrayWrapper(allSecrets.toArray.flatMap(p => PrivateKey25519Serializer.toBytes(p)))))
    HWallet(seed, store)
  }

  def treasurySecrets: Set[TreasurySecret] = store.get(TreasurySecretsKey)
    .map(b => TreasurySecretCompanion.parseBatch(b.data).toSet).getOrElse(Set.empty[TreasurySecret])

  def treasurySecrets(role: Role, epochId: Long): Set[TreasurySecret] =
    treasurySecrets.filter(s => s.role == role && s.epochId == epochId)

  def treasuryPubKeys(role: Role, epochId: Long): Set[PubKey] =
    treasurySecrets(role, epochId).map(_.pubKey)

  def treasurySecretbyPubKey(pubKey: PubKey): Option[TreasurySecret] =
    treasurySecrets.find(s => s.pubKey.equals(pubKey))

  def generateNewTreasurySecret(role: Role, epochId: Long): PubKey = {
    val prevTrSecrets = treasurySecrets
    val (priv, pub) = TreasuryManager.cs.createKeyPair // TODO: keys should be generated from on a particular seed that includes role,epochId,nonce
    val newTrSecret = TreasurySecret(role, epochId, priv, pub)
    val allTrSecrets: Set[TreasurySecret] = Set(newTrSecret) ++ prevTrSecrets
    store.update(ByteArrayWrapper(priv.toByteArray),
      Seq(),
      Seq(TreasurySecretsKey -> ByteArrayWrapper(TreasurySecretCompanion.batchToBytes(allTrSecrets.toSeq))))

    newTrSecret.pubKey
  }

  //we do not process offchain (e.g. by adding them to the wallet)
  override def scanOffchain(tx: SimpleBoxTransaction): HWallet = this

  override def scanOffchain(txs: Seq[SimpleBoxTransaction]): HWallet = this

  override def scanPersistent(modifier: HybridBlock): HWallet = {
    log.debug(s"Applying modifier to wallet: ${Base58.encode(modifier.id)}")
    val changes = HBoxStoredState.changes(modifier).get

    val newBoxes = changes.toAppend.filter(s => secretByPublicImage(s.box.proposition).isDefined).map(_.box).map { box =>
      val boxTransaction = modifier.transactions.find(t => t.newBoxes.exists(tb => tb.id sameElements box.id))
      val txId = boxTransaction.map(_.id).getOrElse(Array.fill(32)(0: Byte))
      val ts = boxTransaction.map(_.timestamp).getOrElse(modifier.timestamp)
      val wb = WalletBox[PublicKey25519Proposition, PublicKey25519NoncedBox](box, txId, ts)(PublicKey25519NoncedBoxSerializer)
      ByteArrayWrapper(box.id) -> ByteArrayWrapper(wb.bytes)
    }

    val boxIdsToRemove = changes.toRemove.view.map(_.boxId).map(ByteArrayWrapper.apply)
    val newBoxIds: ByteArrayWrapper = ByteArrayWrapper(newBoxes.toArray.flatMap(_._1.data) ++
      boxIds.filter(bi => !boxIdsToRemove.exists(_.data sameElements bi)).flatten)
    store.update(ByteArrayWrapper(modifier.id), boxIdsToRemove, Seq(BoxIdsKey -> newBoxIds) ++ newBoxes)
    log.debug(s"Successfully applied modifier to wallet: ${Base58.encode(modifier.id)}")

    HWallet(seed, store)
  }

  // TODO: is it ok that Secrets and TreasurySecrets are rolled back too?. Probably private keys should never been deleted.
  override def rollback(to: VersionTag): Try[HWallet] = Try {
    if (store.lastVersionID.exists(_.data sameElements to)) {
      this
    } else {
      log.debug(s"Rolling back wallet to: ${Base58.encode(to)}")
      store.rollback(ByteArrayWrapper(to))
      log.debug(s"Successfully rolled back wallet to: ${Base58.encode(to)}")
      HWallet(seed, store)
    }
  }

  override type NVCT = this.type

}

object HWallet {

  def walletFile(settings: ScorexSettings): File = {
    settings.wallet.walletDir.mkdirs()

    new File(s"${settings.wallet.walletDir.getAbsolutePath}/wallet.dat")
  }

  def exists(settings: ScorexSettings): Boolean = walletFile(settings).exists()

  def readOrGenerate(settings: ScorexSettings, seed: ByteStr): HWallet = {
    val wFile = walletFile(settings)
    wFile.mkdirs()
    val boxesStorage = new LSMStore(wFile, maxJournalEntryCount = 10000)

    Runtime.getRuntime.addShutdownHook(new Thread() {
      override def run(): Unit = {
        boxesStorage.close()
      }
    })

    HWallet(seed, boxesStorage)
  }

  def readOrGenerate(settings: ScorexSettings): HWallet = {
    readOrGenerate(settings, settings.wallet.seed)
  }

  def readOrGenerate(settings: ScorexSettings, seed: ByteStr, accounts: Int): HWallet =
    (1 to accounts).foldLeft(readOrGenerate(settings, seed)) { case (w, _) =>
      w.generateNewSecret()
    }

  def readOrGenerate(settings: ScorexSettings, accounts: Int): HWallet =
    (1 to accounts).foldLeft(readOrGenerate(settings)) { case (w, _) =>
      w.generateNewSecret()
    }

  //wallet with applied initialBlocks
  def genesisWallet(settings: ScorexSettings, initialBlocks: Seq[HybridBlock]): HWallet = {
    initialBlocks.foldLeft(readOrGenerate(settings).generateNewSecret()) { (a, b) =>
      a.scanPersistent(b)
    }
  }
}

case class TreasurySecret(role: Role, epochId: Long, privKey: PrivKey, pubKey: PubKey)

object TreasurySecretCompanion extends Serializer[TreasurySecret] {

  def batchToBytes(batch: Seq[TreasurySecret]): Array[Byte] = {
    batch.foldLeft(Array[Byte]()) { case (acc, s) =>
      val bytes = toBytes(s)
      Bytes.concat(acc, Ints.toByteArray(bytes.length), bytes)
    }
  }

  //@tailrec
  def parseBatch(bytes: Array[Byte]): List[TreasurySecret] =
    if (bytes.length < 4) List()
    else {
      val size = Ints.fromByteArray(bytes.slice(0,4))
      parseBytes(bytes.slice(4, size+4)) match {
        case Success(s) => s :: parseBatch(bytes.drop(size+4))
        case Failure(_) => parseBatch(bytes.drop(size+4))
      }
    }

  def toBytes(s: TreasurySecret): Array[Byte] = {
    val privBytes = s.privKey.toByteArray
    val pubBytes = s.pubKey.getEncoded(true)
    Bytes.concat(
      Array(s.role.id.toByte),
      Longs.toByteArray(s.epochId),
      Ints.toByteArray(privBytes.length),
      privBytes,
      Ints.toByteArray(pubBytes.length),
      pubBytes)
  }

  def parseBytes(bytes: Array[Byte]): Try[TreasurySecret] = Try {
    val role: Role = Role(bytes(0))
    val epochID = Longs.fromByteArray(bytes.slice(1,9))
    val privSize = Ints.fromByteArray(bytes.slice(9,13))
    val privKey = new PrivKey(bytes.slice(13,privSize+13))
    val pubSize = Ints.fromByteArray(bytes.slice(privSize+13,privSize+17))
    val pubKey = TreasuryManager.cs.decodePoint(bytes.slice(privSize+17,privSize+17+pubSize))

    TreasurySecret(role, epochID, privKey, pubKey)
  }
}