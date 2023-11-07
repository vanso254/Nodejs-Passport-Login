if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const mongoose=require('mongoose')
const User=require('./userModels')

//connecting the database
mongoose.connect('mongodb://127.0.0.1:27017/nodePassportLogin',{
    useNewUrlParser: true, useUnifiedTopology: true
})


const initializePassport = require('./passport-config')
initializePassport(
  passport,
  email => {
    return User.findOne({ email: email }).exec();
  },
  id => {
    return User.findById(id).exec();
  }
)



app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10)
  const newUser = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword
})
  try {
    const user = await newUser.save();
    console.log(user)
    res.redirect('/login')
  } catch(err) {
    console.log(err)
    res.redirect('/register')
  }
})

app.post('/logout', function(req, res, next){
  req.logout(function(err) {
    if (err) { return next(err)
     }
    res.redirect('/')
  })
})


function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

app.listen(3000)