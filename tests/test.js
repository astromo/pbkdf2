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

test('should parse the correct options', function (t) {
  t.plan(3)
  var p = new PBKDF2()

  var options = p._parse('sha256:100000:bXktc2FsdA==:6D795F646572697665645F6B6579')
  t.deepEqual(options, {
    algorithm: 'sha256',
    iterations: 100000,
    salt_length: 7,
    key_length: 14
  })
  t.equal(p.derived_key, '6D795F646572697665645F6B6579')
  t.equal(p.salt, 'bXktc2FsdA==')
})

test('should throw an error when input is invalid', function (t) {
  t.plan(1)
  var p = new PBKDF2()

  t.throws(function () {
    p._parse('sha256:100000:bXktc2Fsd:6D795F646572697665645F6B657')
  })
})
