var PBKDF2 = require('../index')
var test = require('tape')
var calculated_hash

test('should generate a correct password hash', function (t) {
  t.plan(1)
  var password = new PBKDF2()

  password.create('test123', function (err, hash) {
    if (err) t.fail(err)
    calculated_hash = hash
    t.ok(true)
  })
})

test('should validate the correct password', function (t) {
  t.plan(1)
  var password = new PBKDF2(calculated_hash)

  password.validate('test123', function (err, valid) {
    if (err) t.fail(err)
    t.equal(valid, true)
  })
})

test('should invalidate when incorrect password', function (t) {
  t.plan(1)
  var password = new PBKDF2(calculated_hash)

  password.validate('test1234', function (err, valid) {
    if (err) t.fail(err)
    t.equal(valid, false)
  })
})
