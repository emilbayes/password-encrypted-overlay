# `password-encrypted-overlay`

> Password encrypted overlay to Random Access modules

## Usage

### Create and write

```js
var PasswordEncryptedOverlay = require('password-encrypted-overlay')
var raf = require('random-access-file') // or random-access-memory or ...

var passwordBuffer = // ... (preferably sodium SecureBuffer)
// Note that the passwordBuffer is "consumed" by the constructor, ie. it will
// be cleared when a key has been derived from the password. If you need to keep
// the password, you should copy it and pass in the copy
var storage = new PasswordEncryptedOverlay(raf('./secret.enc'), passwordBuffer)

storage.init(PasswordEncryptedOverlay.MODERATE, function (err) {
  if (err) throw err

  storage.write(Buffer.from('My encrypted file'), function (err) {
    if (err) throw err

    storage.destroy()
    storage = null
  })
})
```

### Read

```js
var PasswordEncryptedOverlay = require('password-encrypted-overlay')
var raf = require('random-access-file')

var passwordBuffer = // ... (preferably sodium SecureBuffer)
var storage = new PasswordEncryptedOverlay(raf('./secret.enc'), passwordBuffer)

storage.read(function (err, buf) {
  if (err) throw err

  console.log(buf) // buf is sodium SecureBuffer, contains 'My encrypted file'
})
```

## API

### `var peo = new PasswordEncryptedOverlay(raf, password)`
Create a new instance. If this is a brand new raf, you must call `peo.init`
after. Otherwise you can start reading/writing. Password must be a `Buffer`,
optimally a `SecureBuffer`. `password` will be zero'ed out after it has been
derived into a key. Please copy this if you want to manage the password after
key derivation.

### `peo.init({memlimit, opslimit}, cb(err))`
Initialize a new raf with the given hardness settings. See the constants below
for some predefined settings. `memlimit` is the number of bytes used, rounded
down to the nearest kilobyte. `opslimit` is the number of passes over the memory.
Both must be Numbers and fit in a 32-bit unsigned integer.

### `peo.read(cb(err, secureBuf))`
Read and decrypt into a `SecureBuffer` from the raf. If an `err` is given in the
callback, the `peo` will have been destroyed before.

### `peo.write(buf, cb(err))`
Encrypt and write a `Buffer` to the raf. This updates the settings and rotates
the nonce. If an `err` is given in the callback, the `peo` will have been
destroyed before.

### `peo.destroy()`
Destroy the internal state, including zero'ing all internal data.
Makes all other methods unusable hereafter

### Constants

* `PasswordEncryptedOverlay.INTERACTIVE`
  - `PasswordEncryptedOverlay.MEMLIMIT_INTERACTIVE`
  - `PasswordEncryptedOverlay.OPSLIMIT_INTERACTIVE`
* `PasswordEncryptedOverlay.MODERATE`
  - `PasswordEncryptedOverlay.MEMLIMIT_MODERATE`
  - `PasswordEncryptedOverlay.OPSLIMIT_MODERATE`
* `PasswordEncryptedOverlay.SENSITIVE`
  - `PasswordEncryptedOverlay.MEMLIMIT_SENSITIVE`
  - `PasswordEncryptedOverlay.OPSLIMIT_SENSITIVE`

## Install

```sh
npm install password-encrypted-overlay
```

## License

[ISC](LICENSE)
