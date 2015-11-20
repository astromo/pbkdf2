var assert = require('assert')
var PBKDF2 = require('../index')

describe('PBKDF2 password library', function () {

  var calculated_hash

  it('should generate a correct password hash', function (done) {

    var password = new PBKDF2()
    password.create('test123', function(err, hash) {
      if (err) throw err
      calculated_hash = hash
      done()
    })

  })

  it('should validate the correct password', function (done) {

    password = new PBKDF2(calculated_hash)

    password.validate('test123', function (err, valid) {
      if (err) throw err
      assert.equal(valid, true)
      done()
    })

  })

  it('should invalidate when incorrect password', function (done) {

    password = new PBKDF2(calculated_hash)

    password.validate('test1234', function (err, valid) {
      if (err) throw err
      assert.equal(valid, false)
      done()
    })

  })

})
