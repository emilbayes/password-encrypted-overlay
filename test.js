var test = require('tape')
var ram = require('random-access-memory')

var PasswordEncryptedOverlay = require('.')

test('Write and reread', function (assert) {
  var mem = ram()
  var pwd = Buffer.from('secret') // use sodium buffers in real life
  var msg = Buffer.from('Hello world')
  var p = new PasswordEncryptedOverlay(mem, Buffer.from(pwd))
  p.init(PasswordEncryptedOverlay.INTERACTIVE, function (err) {
    if (err) return assert.end(err)

    p.write(msg, onwrite)
  })

  function onwrite (err) {
    if (err) return assert.end(err)

    var memCopy = mem.toBuffer() // use mem.toBuffer
    var p2 = new PasswordEncryptedOverlay(mem, Buffer.from(pwd))

    p2.read(function (err, buf) {
      if (err) return assert.end(err)

      assert.same(msg, buf)
      assert.same(memCopy, mem.toBuffer())

      assert.end()
    })
  }
})

test('Write, read and write shorter', function (assert) {
  var mem = ram()
  var pwd = Buffer.from('secret') // use sodium buffers in real life
  var msg = Buffer.from('Hello world')
  var p = new PasswordEncryptedOverlay(mem, Buffer.from(pwd))
  p.init(PasswordEncryptedOverlay.INTERACTIVE, function (err) {
    if (err) return assert.end(err)

    p.write(msg, onwrite)
  })

  function onwrite (err) {
    if (err) return assert.end(err)

    p.write(msg.slice(0, 5), onwrite2)
  }

  function onwrite2 (err) {
    if (err) return assert.end(err)

    var memCopy = mem.toBuffer() // use mem.toBuffer
    var p2 = new PasswordEncryptedOverlay(mem, Buffer.from(pwd))

    p2.read(function (err, buf) {
      if (err) return assert.end(err)

      assert.same(msg.slice(0, 5), buf)
      assert.same(memCopy, mem.toBuffer())

      assert.end()
    })
  }
})
