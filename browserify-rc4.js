var CipherBase = require('cipher-base')
var inherits = require('inherits')
var Buffer = require('safe-buffer').Buffer

function rc4impl (key) {
  var sBox = Array.from(Array(256).keys())
  var i = 0
  var j = 0
  for (i = 0; i < 256; i++) {
    j = (j + sBox[i] + key[i % key.length]) & 0xFF
    var tmp = sBox[i]
    sBox[i] = sBox[j]
    sBox[j] = tmp
  }
  i = 0
  j = 0
  return function getValue () {
    i = (i + 1) & 0xFF
    j = (j + sBox[i]) & 0xFF
    var tmp = sBox[i]
    sBox[i] = sBox[j]
    sBox[j] = tmp
    return sBox[(sBox[i] + sBox[j]) & 0xFF]
  }
}

function RC4 (key, iv) {
  CipherBase.call(this)

  // throw if an IV was passed, to mimic Node
  if (iv && iv.length) {
    throw Error('Invalid IV length')
  }

  if (typeof key === 'string') key = Buffer.from(key)
  this.fn = rc4impl(key)
}

RC4.prototype._update = function (data) {
  data = Buffer.from(data) // create copy
  for (var i = 0; i < data.length; i++) {
    data[i] ^= this.fn()
  }
  return data
}

RC4.prototype._final = function () {
  return Buffer.alloc(0)
}

inherits(RC4, CipherBase)
module.exports = RC4
module.exports.impl = rc4impl
