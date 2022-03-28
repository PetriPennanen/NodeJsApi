const express = require('express')
const bodyParser = require('body-parser')
const users = require('./routes/users').router
const postings = require('./routes/postings').router
const login = require('./routes/login')
const upload = require('./routes/upload')
const mongoose = require('mongoose')
const mongodb_uri = process.env.MONGODB_URI || require('./secrets').mongodb_uri
const cors = require('cors')

const app = express()
// heroku
const herokuPort = process.env.PORT || 80
const localhostPort = 3001

app.use(bodyParser.json())
app.use(cors())

app.use('/users', users)
app.use('/postings', postings)
app.use('/login', login)

app.get('/', (req, res) => {
  res.status(200).json({
    documentation:
      'https://mikael-k.stoplight.io/docs/web-store/YXBpOjIzMjY3NjQz-web-store',
    routes: ['/users', '/postings', '/login', '/upload'],
  })
})

let serverInstance = null

module.exports = {
  start: function () {
    app.use('/upload', upload)
    mongoose.connect(mongodb_uri, () => {
      serverInstance = app.listen(localhostPort)
    })
  },
  startDev: function () {
    console.log('Connecting to localhost database...')
    mongoose.connect(
      'mongodb://localhost/localhostdb',
      () => {
        console.log('Connected to localhost MongoDB')
        serverInstance = app.listen(localhostPort)
        console.log(`Server running on localhost:${localhostPort}`)
      },
      (e) => console.error(e)
    )
  },
  close: function () {
    serverInstance.close()
  },
}
