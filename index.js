const sodium = require('sodium-native')
const assert = require('nanoassert')
const thunky = require('thunky')
const mutexify = require('mutexify')

function isUInt32 (x) {
  return x >= 0 && x <= 0xffffffff
}

function isInt32 (x) {
  return x >= -0x7fffffff && x <= 0x7fffffff
}

class KeyHeader {
  constructor (buf) {
    assert(buf.byteLength >= KeyHeader.BYTES, 'KeyHeader buf too small')
    this.buffer = buf
  }

  set alg (val) {
    assert(isInt32(val), 'KeyHeader.alg must be int32')
    this.rotateNonce()
    return this.buffer.writeInt32LE(val, 0)
  }

  get alg () {
    // due to libsodium
    return this.buffer.readInt32LE(0)
  }

  set opslimit (val) {
    assert(isUInt32(val), 'KeyHeader.opslimit must be uint32')
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 4)
  }

  get opslimit () {
    return this.buffer.readUInt32LE(4)
  }

  set memlimit (val) {
    assert(isUInt32(val), 'KeyHeader.memlimit must be uint32')
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 8)
  }

  get memlimit () {
    return this.buffer.readUInt32LE(8)
  }

  get nonce () {
    return this.buffer.subarray(12, 12 + sodium.crypto_pwhash_SALTBYTES)
  }

  init (opslimit, memlimit) {
    this.alg = sodium.crypto_pwhash_ALG_ARGON2ID13
    this.opslimit = opslimit
    this.memlimit = memlimit
  }

  validate () {
    assert(this.alg === sodium.crypto_pwhash_ALG_ARGON2ID13)
  }

  rotateNonce () {
    sodium.randombytes_buf(this.nonce)
  }
}
KeyHeader.BYTES = 12 + sodium.crypto_pwhash_SALTBYTES

class DataHeader {
  constructor (buf) {
    assert(buf.byteLength >= DataHeader.BYTES, 'DataHeader buffer too small')
    this.buffer = buf
  }

  set alg (val) {
    assert(isInt32(val))
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 0)
  }

  get alg () {
    return this.buffer.readUInt32LE(0)
  }

  get nonce () {
    return this.buffer.subarray(4, 4 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  }

  init () {
    this.alg = 1
  }

  validate () {
    assert(this.alg === 1)
  }

  rotateNonce () {
    sodium.randombytes_buf(this.nonce)
  }
}
DataHeader.BYTES = 4 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

class PasswordEncryptedBuffer {
  constructor (buf) {
    assert(buf.byteLength >= PasswordEncryptedBuffer.BYTES, 'PasswordEncryptedBuffer buffer too small')
    this.destroyed = false

    this.key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    this.buffer = buf

    this._keyHeader = new KeyHeader(this.buffer.subarray(4, 4 + KeyHeader.BYTES))
    this._dataHeader = new DataHeader(this.buffer.subarray(4 + KeyHeader.BYTES, 4 + KeyHeader.BYTES + DataHeader.BYTES))
  }

  set version (val) {
    assert(isUInt32(val))
    return this.buffer.writeUInt32LE(val, 0)
  }

  get version () {
    return this.buffer.readUInt32LE(0)
  }

  init (opslimit, memlimit) {
    this.version = 1
    this._keyHeader.init(opslimit, memlimit)
    this._dataHeader.init()
  }

  validate () {
    assert(this.version === 1)
    this._keyHeader.validate()
    this._dataHeader.validate()
  }

  deriveKey (passphrase, cb) {
    sodium.crypto_pwhash_async(
      this.key,
      passphrase,
      this._keyHeader.nonce,
      this._keyHeader.opslimit,
      this._keyHeader.memlimit,
      this._keyHeader.alg,
      (err) => {
        return cb(err, this.key)
      }
    )
  }

  decrypt (ciphertext) {
    const plaintext = sodium.sodium_malloc(ciphertext.byteLength - DATA_MAC_BYTES)

    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,
      null,
      ciphertext,
      this._keyHeader.buffer,
      this._dataHeader.nonce,
      this.key
    )

    return plaintext
  }

  encrypt (plaintext) {
    const ciphertext = Buffer.alloc(plaintext.byteLength + DATA_MAC_BYTES)

    this._dataHeader.rotateNonce()
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext,
      plaintext,
      this._keyHeader.buffer,
      null,
      this._dataHeader.nonce,
      this.key
    )

    return ciphertext
  }

  destroy () {
    sodium.sodium_memzero(this.key)
    sodium.sodium_memzero(this.buffer)

    this.destroyed = true
  }
}
PasswordEncryptedBuffer.BYTES = 4 + KeyHeader.BYTES + DataHeader.BYTES

const PASSPHRASE_CAP = Symbol('PASSPHRASE_CAP')
const DATA_MAC_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

class PasswordEncryptedOverlay {
  constructor (raf, passphrase) {
    assert(raf, 'raf must be given')
    assert(passphrase.byteLength, 'passphrase must be Buffer-like')

    this.raf = raf
    this[PASSPHRASE_CAP] = passphrase

    this.peb = null
    this.mutex = mutexify()

    this.destroyed = false

    this.open = thunky((cb) => {
      if (this.destroyed === true) return this.destroy(new Error('Destroyed'), cb)

      this.raf.read(0, PasswordEncryptedBuffer.BYTES, (err, headerBuf) => {
        if (this.destroyed === true) return this.destroy(new Error('Destroyed'), cb)
        if (err) return this.destroy(err, cb)

        try {
          this.peb = new PasswordEncryptedBuffer(headerBuf)
          this.peb.validate()
        } catch (ex) {
          return this.destroy(ex, cb)
        }

        this.peb.deriveKey(passphrase, (err) => {
          if (this.destroyed === true) return this.destroy(new Error('Destroyed'), cb)
          if (err) return this.destroy(err, cb)

          sodium.sodium_memzero(passphrase)
          this[PASSPHRASE_CAP] = null

          return cb(null)
        })
      })
    })
  }

  init (settings, cb) {
    if (this.destroyed === true) return this.destroy(new Error('Destroyed'))

    assert(settings)
    assert(settings.opslimit)
    assert(settings.memlimit)

    var initPeb = new PasswordEncryptedBuffer(Buffer.alloc(PasswordEncryptedBuffer.BYTES))
    initPeb.init(settings.opslimit, settings.memlimit)
    this.mutex((release) => {
      const done = release.bind(null, cb)
      if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)

      this.raf.write(0, initPeb.buffer, (err) => {
        initPeb.destroy()
        if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)
        if (err) return this.destroy(err, done)

        this.open(done)
      })
    })
  }

  read (cb) {
    if (this.destroyed === true) return this.destroy(new Error('Destroyed'))

    this.open((err) => {
      if (this.destroyed === true) return this.destroy(new Error('Destroyed'), cb)
      if (err) return this.destroy(err, cb)

      this.mutex((release) => {
        const done = release.bind(null, cb)
        if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)

        this.raf.stat((err, stat) => {
          if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)
          if (err) return this.destroy(err, done)
          var dataByteLength = stat.size - PasswordEncryptedBuffer.BYTES

          if (dataByteLength < DATA_MAC_BYTES) return this.destroy(new Error('Invalid data segment'), done)

          this.raf.read(PasswordEncryptedBuffer.BYTES, dataByteLength, (err, dataBuf) => {
            if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)
            if (err) return this.destroy(err, done)

            try {
              var plaintext = this.peb.decrypt(dataBuf)
            } catch (ex) {
              return this.destroy(ex, done)
            }

            return done(null, plaintext)
          })
        })
      })
    })
  }

  write (dataBuf, cb) {
    if (this.destroyed === true) return this.destroy(new Error('Destroyed'))

    this.open((err) => {
      if (this.destroyed === true) return this.destroy(new Error('Destroyed'), cb)
      if (err) return this.destroy(err, cb)

      try {
        var ciphertext = this.peb.encrypt(dataBuf)
      } catch (ex) {
        return this.destroy(ex, cb)
      }

      const fileBuffer = Buffer.concat([this.peb.buffer, ciphertext])

      this.mutex((release) => {
        const done = release.bind(null, cb)
        if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)

        this.raf.write(0, fileBuffer, (err) => {
          if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)
          if (err) return this.destroy(err, done)

          this.raf.del(fileBuffer.byteLength, Infinity, (err) => {
            if (this.destroyed === true) return this.destroy(new Error('Destroyed'), done)
            if (err) return this.destroy(err, done)

            return done(null)
          })
        })
      })
    })
  }

  // eslint-disable-next-line handle-callback-err
  destroy (err, cb) {
    if (this.destroyed === true) {
      if (this[PASSPHRASE_CAP]) {
        sodium.sodium_memzero(this[PASSPHRASE_CAP])
        this[PASSPHRASE_CAP] = null
      }

      this.peb.destroy()

      this.destroyed = true
    }

    if (cb) return cb(err)
    if (err) throw err
  }
}

PasswordEncryptedOverlay.MEMLIMIT_INTERACTIVE = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
PasswordEncryptedOverlay.OPSLIMIT_INTERACTIVE = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
PasswordEncryptedOverlay.INTERACTIVE = {
  memlimit: PasswordEncryptedOverlay.MEMLIMIT_INTERACTIVE,
  opslimit: PasswordEncryptedOverlay.OPSLIMIT_INTERACTIVE
}

PasswordEncryptedOverlay.MEMLIMIT_MODERATE = sodium.crypto_pwhash_MEMLIMIT_MODERATE
PasswordEncryptedOverlay.OPSLIMIT_MODERATE = sodium.crypto_pwhash_OPSLIMIT_MODERATE
PasswordEncryptedOverlay.MODERATE = {
  memlimit: PasswordEncryptedOverlay.MEMLIMIT_MODERATE,
  opslimit: PasswordEncryptedOverlay.OPSLIMIT_MODERATE
}

PasswordEncryptedOverlay.MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE
PasswordEncryptedOverlay.OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE
PasswordEncryptedOverlay.SENSITIVE = {
  memlimit: PasswordEncryptedOverlay.MEMLIMIT_SENSITIVE,
  opslimit: PasswordEncryptedOverlay.OPSLIMIT_SENSITIVE
}

module.exports = PasswordEncryptedOverlay
