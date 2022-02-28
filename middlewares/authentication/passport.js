const bcrypt = require('bcryptjs')
const passport = require('passport')
const users = require('../../routes/users').users
const avain = require('../../secrets')

/******** Middleware funktio passport-HTTP autentikointiin *********/
const { BasicStrategy } = require('passport-http')

passport.use(
  new BasicStrategy(function (username, password, done) {
    // console.log('Login from: ', username)
    let user = users.find(
      (user) =>
        user.username === username &&
        bcrypt.compareSync(password, user.password)
    )
    if (user != undefined) {
      done(null, { user })
    } else {
      // console.log('User not found')
      done(null, false)
    }
  })
)

/********** Middleware funktio passport-JWT autentikointiin **********/
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt

const jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken()
jwtOptions.secretOrKey = process.env.avain || avain

passport.use(
  new JwtStrategy(jwtOptions, function (jwt_payload, done) {
    const user = users.find((u) => u.userId === jwt_payload.userId)
    done(null, user)
  })
)

module.exports = passport
