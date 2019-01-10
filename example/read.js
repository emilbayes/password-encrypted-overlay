var PasswordEncryptedOverlay = require('..')
var raf = require('random-access-file')

var passwordBuffer = Buffer.from('Hello world') // Ideally sodium.sodium_malloc instead
PasswordEncryptedOverlay.open(raf('./secret.enc'), passwordBuffer, function (err, storage) {
  if (err) throw err

  storage.read((err, buf) => {
    if (err) throw err

    console.log(buf.toString()) // buf is sodium SecureBuffer, contains 'My encrypted file'
  })
})
