const signer = require('./')
const crypto = require('crypto')
const test = require('tape')
const rlp = require('eth-serde').rlp
const vectors = require('./vectors.json')

test('sign', t => {
  var tx = {
    nonce: Buffer.from('00', 'hex'),
    gasPrice: Buffer.from('09184e72a000', 'hex'),
    gasLimit: Buffer.from('2710', 'hex'),
    to: Buffer.from('0000000000000000000000000000000000000000', 'hex'),
    value: Buffer.from('00', 'hex'),
    data: Buffer.from('7f7465737432000000000000000000000000000000000000000000000000000000600057', 'hex'),
  }

  var privKey = crypto.randomBytes(32)
  const signed = signer.sign(tx, privKey)
  t.ok(signer.verify(signed.tx))
  t.end()
})

test('sign: string input', t => {
  var tx = {
    nonce: '0x00',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x2710',
    to: '0x0000000000000000000000000000000000000000',
    value: '0x00',
    data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057'
  }

  var privKey = crypto.randomBytes(32)
  const signed = signer.sign(tx, privKey)
  t.ok(signer.verify(signed.tx))
  t.end()
})

test('verify: vectors', t => {
  var raw = Buffer.from('f86c81dc8501984ab39182520894361c7a56cb86ac9c3fe3f47504ac1da63fc6137f872516ff52ce08008026a0e74da2d5c587083586fa877627c47b5925c1e60453bf83601a55f9775415c142a0187e9e8a3b36677961669841bb1f3005cd6578af0e0f7fc7b164b0bd06e6382d', 'hex')
  var tx = format(raw)

  var chainId = tx.v[0] > 30 ? 1 : null
  t.ok(signer.verify(tx, chainId))

  for (let v of vectors.map(a => Buffer.from(a.slice(2), 'hex'))) {
    var tx = format(v)
    t.ok(signer.verify(tx))
  }

  t.end()
})

test('verify: vectors', t => {
  var raw = Buffer.from('f86c81dc8501984ab39182520894361c7a56cb86ac9c3fe3f47504ac1da63fc6137f872516ff52ce08008026a0e74da2d5c587083586fa877627c47b5925c1e60453bf83601a55f9775415c142a0187e9e8a3b36677961669841bb1f3005cd6578af0e0f7fc7b164b0bd06e6382d', 'hex')
  var tx = format(raw, true, true)
  var chainId = tx.v[0] > 30 ? 1 : null
  t.ok(signer.verify(tx, chainId))

  for (let v of vectors.map(a => Buffer.from(a.slice(2), 'hex'))) {
    var tx = format(v, true, true)
    t.ok(signer.verify(tx))
  }

  t.end()
})

test('verify: vectors raw buffer', t => {
  var raw = Buffer.from('f86c81dc8501984ab39182520894361c7a56cb86ac9c3fe3f47504ac1da63fc6137f872516ff52ce08008026a0e74da2d5c587083586fa877627c47b5925c1e60453bf83601a55f9775415c142a0187e9e8a3b36677961669841bb1f3005cd6578af0e0f7fc7b164b0bd06e6382d', 'hex')
  t.ok(signer.verify(raw))

  for (let v of vectors.map(a => Buffer.from(a.slice(2), 'hex'))) {
    t.ok(signer.verify(v))
  }

  t.end()
})

test("verify: vectors raw string with '0x'", t => {
  var raw = Buffer.from('f86c81dc8501984ab39182520894361c7a56cb86ac9c3fe3f47504ac1da63fc6137f872516ff52ce08008026a0e74da2d5c587083586fa877627c47b5925c1e60453bf83601a55f9775415c142a0187e9e8a3b36677961669841bb1f3005cd6578af0e0f7fc7b164b0bd06e6382d', 'hex')
  t.ok(signer.verify(raw))

  for (let v of vectors) {
    t.ok(signer.verify(v))
  }

  t.end()
})

test('sign: vectors', t => {
  for (let v of vectors.map(a => Buffer.from(a.slice(2), 'hex'))) {
    var key = crypto.randomBytes(32)
    var tx = format(v, false)
    var chainId = format.v > 30 ? 1 : null
    const signed = signer.sign(tx, key, chainId)
    t.ok(signer.verify(signed.tx, chainId))
  }

  t.end()
})

function format (str, toVerify = true, string = false) {
  var items = rlp.decode(str)

  if (string) items = items.map(a => 
    typeof a === 'number'
      ? '0x' + a.toString(16)
      : '0x' + a.toString('hex'))

  var obj = {}
  obj.nonce = Buffer.from([items[0]])
  obj.gasPrice = items[1]
  obj.gasLimit = items[2]
  obj.to = items[3]
  obj.value = items[4]
  obj.data = items[5]

  if (toVerify) {
    obj.v = Buffer.from([items[6]])
    obj.r = items[7]
    obj.s = items[8]
  }

  if (string) obj.nonce = '0x' + obj.nonce.toString('hex')
    if (string && obj.v) obj.v = '0x' + obj.v.toString('hex')

  format.v = items[6]
  return obj
}
