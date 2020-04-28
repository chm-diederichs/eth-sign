const { rlp } = require('eth-serde')
const secp = require('secp256k1-native')
const keccak = require('sha3-wasm').keccak256
const assert = require('nanoassert')

module.exports = {
  sign,
  verify
}

function sign (tx, privKey, chainId) {
  var txDigest = digest(tx, chainId)
  var sigHash = rlpHash(txDigest)
  var sig = ecsign(sigHash, privKey, chainId)

  var obj = {}
  Object.assign(obj, tx)
  Object.assign(obj, sig)

  var raw = rlp.encode(digest(obj))
  obj.hash = keccak().update(raw).digest()

  return {
    raw,
    tx: obj
  }
}

function verify (tx) {
  if (tx instanceof Uint8Array || typeof tx === 'string') {
    var obj = format(tx)
    return verify(obj)
  }

  var v = tx.v instanceof Uint8Array ? parseNumber(tx.v) : tx.v

  var chainId = getChainId(v)
  var parity = chainId ? v - (2 * chainId + 35) : v - 27

  var txDigest = digest(tx, chainId)
  if (!chainId) txDigest = txDigest.slice(0, 6)

  var sigHash = rlpHash(txDigest)
  
  var sig = Buffer.alloc(65)
  sig.set(reverse(parseHex(tx.r)))
  sig.set(reverse(parseHex(tx.s)), 32)
  sig.writeUInt8(parity, 64)
  
  return ecverify(sigHash, sig)
}

function rlpHash (a) {
  return keccak().update(rlp.encode(a)).digest()
}

function ecsign (digest, privKey, chainId) {
  var obj = {}
  
  var ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)
  var sig = Buffer.alloc(secp.secp256k1_ecdsa_recoverable_SIGBYTES)

  secp.secp256k1_ecdsa_sign_recoverable(ctx, sig, digest, privKey)

  var parity = sig.readUInt8(64)

  obj.r = reverse(sig.slice(0, 32))
  obj.s = reverse(sig.slice(32, 64))
  obj.v = chainId ? parity + (chainId * 2 + 35) : parity + 27

  return obj
}

function ecverify (digest, sig) {
  var digest
  var pubkey = Buffer.alloc(secp.secp256k1_PUBKEYBYTES)
  var ctx = secp.secp256k1_context_create(secp.secp256k1_context_VERIFY)

  secp.secp256k1_ecdsa_recover(ctx, pubkey, sig, digest)

  var sig64 = Buffer.alloc(64)
  secp.secp256k1_ecdsa_recoverable_signature_convert(ctx, sig64, sig)
  
  return secp.secp256k1_ecdsa_verify(ctx, sig64, digest, pubkey)
}

function digest (obj, chainId) {
  var items = []

  items.push(parseHex(obj.nonce))
  items.push(parseHex(obj.gasPrice))
  items.push(parseHex(obj.gasLimit))
  items.push(parseHex(obj.to))
  items.push(parseHex(obj.value))
  items.push(parseHex(obj.data))

  // implement EIP155
  if (chainId) {
    items.push(Buffer.from([chainId]))
    items.push(Buffer.alloc(0))
    items.push(Buffer.alloc(0))
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
      throw new Error('failed to parse number: buffer too large')
  }
}

function reverse (buf) {
  let tmp = []

  var i
  for (i = 0; i < Math.ceil(buf.byteLength / 2); i++) {
    tmp.push(buf[i])
    buf[i] = buf[buf.length - 1 -i]
  }

  var offset = i
  for (; i < buf.byteLength; i++) {
    buf[i] = tmp[2 * offset - i - 1]
  }

  return buf
}

function format (raw) {
  if (typeof raw === 'string') raw = parseHex(raw)
  assert(raw instanceof Uint8Array && raw.byteLength,
    'tx should be passed as bytes or a hex encoded string')

  var items = rlp.decode(raw)

  var obj = {}
  obj.nonce = Buffer.from([items[0]])
  obj.gasPrice = items[1]
  obj.gasLimit = items[2]
  obj.to = items[3]
  obj.value = items[4]
  obj.data = items[5]
  obj.v = Buffer.from([items[6]])
  obj.r = items[7]
  obj.s = items[8]

  return obj
}

function getChainId (v) {
  if (v - 27 > 1) {
    var parity = v - 35 % 2
    return (v - 35 - parity) / 2 
  }

  return null
}

function parseHex (str) {
  if (str[1] === 'x') return Buffer.from(str.slice(2), 'hex')
  return str
}
