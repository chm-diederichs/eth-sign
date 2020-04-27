# eth-sign

sign and verify ETH transactions

## Install

```sh
npm i -s eth-sign
```

## Usage

```js
var crypto = require('crypto')
var signer = require('eth-sign')

// all fields should be passed as buffers
var tx = {
  nonce: Buffer.from('00', 'hex'),
  gasPrice: Buffer.from('09184e72a000', 'hex'),
  gasLimit: Buffer.from('2710', 'hex'),
  to: Buffer.from('0000000000000000000000000000000000000000', 'hex'),
  value: Buffer.from('00', 'hex'),
  data: Buffer.from('7f7465737432000000000000000000000000000000000000000000000000000000600057', 'hex'),
}

var privKey = crypto.randomBytes(32)

var chainId = 1 // mainnet
const signed = signer.sign(tx, privKey, chainId) // specify chainId for EIP155 digest

signer.verify(signed.tx) // true
signer.verify(signed.raw) // true
signer.verify(signed.raw.toString('hex')) // true

```

## API

#### `signer.sign(tx, privKey, [chainId])`

Sign a `tx` using `privKey`. Returns `{ tx, raw }`, with `raw` being the bytecode of the signed transaction and `tx` of the form: 
```js
{
  nonce,
  gasPrice,
  gasLimit,
  to,
  value,
  data,
  v,          // recovery info for sig
  r,          // sig.r
  s,          // sig.s
  hash        // tx hash
}
```

All fields in `tx` MUST be passed as `buffer`s. `chainId` may be specified to implement EIP155 signature digest, otherwise legacy digest is used by default.

#### `signer.verify(tx)`

Verify a signed `tx`. `tx` should be a signed tx object as above, or a raw tx encoded as a hex string or in a `buffer`. Returns `true` if verification succeeds, `false` otherwise.

## License

[ISC](LICENSE)
