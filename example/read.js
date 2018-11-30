var PasswordEncryptedOverlay = require('.')
var raf = require('random-access-file')

var passwordBuffer = Buffer.from('Hello world') // Ideally sodium.sodium_malloc instead
var storage = new PasswordEncryptedOverlay(raf('./secret.enc'), passwordBuffer)

storage.read(function (err, buf) {
  if (err) throw err

  console.log(buf.toString()) // buf is sodium SecureBuffer, contains 'My encrypted file'
})
