# PBKDF2

This library generates a formatted hash that you can store in your database as a single value.

The format is `ALGORITHM:ITTERATIONS:SALT:DERIVED_KEY`.

## Usage

`var PBKDF2 = require('painless-pbkdf2')`

## Create a password hash
```javascript
var password = new PBKDF2()
password.create('test123', function(err, hash) {
  // hash: (sha256:64000:VImSI/1MUSFHuQzrbelyaKnjDcp7LoZwZRZmc8ErLq4=:708eb4b660fdb56b911abbdc26faae0aa195dbc84e46da23d48ae7630ef25808)
})
```

# Validate a hash
```javascript
var hash = 'sha256:64000:VImSI/1MUSFHuQzrbelyaKnjDcp7LoZwZRZmc8ErLq4=:708eb4b660fdb56b911abbdc26faae0aa195dbc84e46da23d48ae7630ef25808'
password = new PBKDF2(hash)

password.validate('test123', function (err, valid) {
  // valid: (true | false)
})
```
