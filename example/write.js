var PasswordEncryptedOverlay = require('..')
var raf = require('random-access-file') // or random-access-memory or ...

var passwordBuffer = Buffer.from('Hello world') // Ideally sodium.sodium_malloc instead
// Note that the passwordBuffer is "consumed" by the constructor, ie. it will
// be cleared when a key has been derived from the password. If you need to keep
// the password, you should copy it and pass in the copy
PasswordEncryptedOverlay.create(raf('./secret.enc'), passwordBuffer, PasswordEncryptedOverlay.MODERATE, function (err, storage) {
  if (err) throw err

  storage.write(Buffer.from('My encrypted file'), function (err) {
    if (err) throw err

    storage.destroy()
    storage = null
  })
})
