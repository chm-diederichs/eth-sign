const { rlp } = require('eth-serde')
const secp = require('secp256k1-native')
const keccak = require('sha3-wasm').keccak256
const assert = require('nanoassert')

module.exports = {
  sign,
  verify,
  format,
  SECKEYBYTES: secp.secp256k1_SECKEYBYTES
}

function sign (tx, privKey, chainId) {
  assert(tx, 'tx must be given.')
  assert(privKey.byteLength === secp.secp256k1_SECKEYBYTES, '')
  assert(chainId == null ? true : chainId >>> 0 < 110, 'chainId must be less than 110')

  const txDigest = digest(tx, chainId)
  const sigHash = rlpHash(txDigest)
  const sig = ecsign(sigHash, privKey, chainId)

  const obj = Object.assign({}, tx, sig)

  const raw = rlp.encode(digest(obj))
  obj.hash = keccak().update(raw).digest()

  return {
    raw,
    tx: obj
  }
}

function verify (tx) {
  if (tx instanceof Uint8Array || typeof tx === 'string') {
    return verify(format(tx))
  }

  const v = tx.v instanceof Uint8Array ? parseNumber(tx.v) : tx.v

  const chainId = getChainId(v)
  const parity = chainId ? v - (2 * chainId + 35) : v - 27

  let txDigest = digest(tx, chainId)
  if (!chainId) txDigest = txDigest.slice(0, 6)

  const sigHash = rlpHash(txDigest)
  const sig = Buffer.alloc(65)

  sig.set(reverse(parseHex(tx.r)))
  sig.set(reverse(parseHex(tx.s)), 32)
  sig.writeUInt8(parity, 64)

  return ecverify(sigHash, sig)
}

function rlpHash (a) {
  return keccak().update(rlp.encode(a)).digest()
}

function ecsign (digest, privKey, chainId) {
  const obj = {}

  const ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)
  const sig = Buffer.alloc(secp.secp256k1_ecdsa_recoverable_SIGBYTES)

  secp.secp256k1_ecdsa_sign_recoverable(ctx, sig, digest, privKey)

  const parity = sig.readUInt8(64)

  obj.r = reverse(sig.slice(0, 32))
  obj.s = reverse(sig.slice(32, 64))
  obj.v = chainId ? parity + (chainId * 2 + 35) : parity + 27

  return obj
}

function ecverify (digest, sig) {
  const pubkey = Buffer.alloc(secp.secp256k1_PUBKEYBYTES)
  const ctx = secp.secp256k1_context_create(secp.secp256k1_context_VERIFY)

  secp.secp256k1_ecdsa_recover(ctx, pubkey, sig, digest)

  const sig64 = Buffer.alloc(64)
  secp.secp256k1_ecdsa_recoverable_signature_convert(ctx, sig64, sig)

  return secp.secp256k1_ecdsa_verify(ctx, sig64, digest, pubkey)
}

function digest (obj, chainId) {
  assert(obj.nonce)
  assert(obj.gasPrice)
  assert(obj.gas || obj.gasLimit)
  assert(obj.data || obj.to)

  const empty = Buffer.alloc(0)
  const items = []

  const gas = obj.gas || obj.gasLimit
  const data = obj.data || empty
  const value = obj.value || empty
  const to = obj.to || empty

  items.push(stripLeadZeros(parseHex(obj.nonce)))
  items.push(stripLeadZeros(parseHex(obj.gasPrice)))
  items.push(stripLeadZeros(parseHex(gas)))
  items.push(parseHex(to))
  items.push(stripLeadZeros(value))
  items.push(parseHex(data))

  // implement EIP155
  if (chainId) {
    items.push(Buffer.from([chainId]))
    items.push(empty)
    items.push(empty)
  } else {
    // serialise signature if present
    if (obj.v) items.push(Buffer.from([parseHex(obj.v)]))
    if (obj.r) items.push(parseHex(obj.r))
    if (obj.s) items.push(parseHex(obj.s))
  }

  return items
}

function parseNumber (buf) {
  if (!buf) return null

  switch (buf.byteLength) {
    case 1:
      return buf.readUInt8()

    case 2:
      return buf.readUInt16BE()

    case 3:
      return buf.readUInt8() << 16 + buf.readUInt16BE(1)

    case 4:
      return buf.readUInt32BE()

    default:
      assert(false, 'failed to parse number: buffer too large')
  }
}

function reverse (buf) {
  const tmp = []

  let i
  for (i = 0; i < Math.ceil(buf.byteLength / 2); i++) {
    tmp.push(buf[i])
    buf[i] = buf[buf.length - 1 - i]
  }

  const offset = i
  for (; i < buf.byteLength; i++) {
    buf[i] = tmp[2 * offset - i - 1]
  }

  return buf
}

function format (raw) {
  if (typeof raw === 'string') return format(parseHex(raw))
  assert(raw instanceof Uint8Array && raw.byteLength,
    'tx should be passed as bytes or a hex encoded string')

  const items = rlp.decode(raw).map(toBuffer)

  const obj = {}
  obj.nonce = items[0]
  obj.gasPrice = items[1]
  obj.gas = obj.gasLimit = items[2]
  obj.to = items[3]
  obj.value = items[4]
  obj.data = items[5]
  obj.v = items[6]
  obj.r = items[7]
  obj.s = items[8]

  return obj
}

function getChainId (v) {
  if (v - 27 > 1) {
    const parity = (v - 35) % 2
    return (v - 35 - parity) / 2
  }

  return null
}

function parseHex (str) {
  if (str[1] === 'x') return parseHex(str.slice(2))
  if (typeof str === 'string') {
    if (str.length % 2 !== 0) return Buffer.from('0' + str, 'hex')
    return Buffer.from(str, 'hex')
  }
  return str
}

function stripLeadZeros (buf) {
  if (typeof buf === 'string') return stripLeadZeros(Buffer.from(parseHex(buf), 'hex'))

  let i = 0
  while (i < buf.byteLength) {
    if (buf[i] !== 0) break
    i++
  }

  return buf.subarray(i)
}

function toBuffer (a) {
  if (a instanceof Uint8Array) return a

  switch (typeof a) {
    case 'string':
      return Buffer.from(parseHex(a))

    case 'number':
      const buf = Buffer.alloc(4)
      buf.writeUInt32BE(a)
      return stripLeadZeros(buf)

    default:
      assert(false, 'unexpected type: ' + typeof a)
  }
}
