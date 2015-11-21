var _defaults = require('lodash.defaults')
var crypto = require('crypto')
var util = require('util')

function PBKDF2 (options) {
  var defaults = {
    algorithm: 'sha256',

    // iTunes uses 10.000 iterations
    // see http://css.csail.mit.edu/6.858/2015/readings/ios-security-may12.pdf
    iterations: 64000,

    // A good rule of thumb is to use a salt that is the same size as the output of the hash function. For example, the output of SHA256 is 256 bits (32 bytes), so the salt should be at least 32 random bytes.
    // see https://crackstation.net/hashing-security.htm
    salt_length: 32,
    key_length: 32
  }

  this._options = _defaults(options || {}, defaults)

  // the input is a hash we want to validate
  if (typeof options === 'string') {
    this._options = this._parse(options)
  }

  return this
}

/**
 * Creates a password hash containing the algorithm, iterations, salt and derived_key
 * @param  {[type]}   password The password string we want to hash
 * @param  {Function} callback
 */
PBKDF2.prototype.create = function (password, callback) {
  var self = this

  // get random bytes
  crypto.randomBytes(self._options.salt_length, function (err, bytes) {
    if (err) return callback(err)

    var salt = self.salt = bytes.toString('base64')

    self.createPassword(password, salt, function (err, key) {
      if (err) return callback(err)

      var hash = self.format(salt, key)
      return callback(null, hash)
    })
  })
}

/**
 * Create a password using password string and salt
 * @param  {string}   password The password you want to hash
 * @param  {string}   salt     The salt we will be using (base64)
 * @param  {Function} callback
 * @return {[type]}            [description]
 */
PBKDF2.prototype.createPassword = function (password, salt, callback) {
  var self = this

  crypto.pbkdf2(password, self.salt, self._options.iterations, self._options.key_length, 'sha256', function (err, key) {
    if (err) return callback(err)
    key = self.derived_key = key.toString('hex')
    return callback(null, key)
  })
}

/**
 * Format a password to a DB-friendly string
 * @param  {string} salt the salt we used for the hmac
 * @param  {string} key  the derived PBKDF2 key
 * @return {string}      the formatted DB-friendly hash
 */
PBKDF2.prototype.format = function (salt, key) {
  return util.format('%s:%s:%s:%s',
    this._options.algorithm,
    this._options.iterations,
    salt,
    key)
}

/**
 * Parse a formatted hash  into the correct options
 * @param  {string}  hash  formatted hash
 * @return {object}        options object
 */
PBKDF2.prototype._parse = function (hash) {
  // parse options used for the hash
  var args = hash.split(':')
  var options = {
    algorithm: args[0],
    iterations: parseInt(args[1], 10),
    salt_length: new Buffer(args[2], 'base64').length,
    key_length: new Buffer(args[3], 'hex').length
  }
  this._options = options

  this.salt = args[2]
  this.derived_key = args[3]

  return options
}

/**
 * [validate description]
 * @param  {string}   password The password we want to validate it against
 * @param  {Function} callback
 */
PBKDF2.prototype.validate = function (password, callback) {
  var self = this
  var salt = this.salt
  var derived_key = this.derived_key

  self.createPassword(password, salt, function (err, key) {
    return callback(err, key === derived_key)
  })
}

module.exports = PBKDF2
