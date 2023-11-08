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
const MongoStore = require('connect-mongo')(session);


//connecting the database
mongoose.connect('mongodb://127.0.0.1:27017/nodePassportLogin',{
    useNewUrlParser: true, useUnifiedTopology: true
})


const initializePassport = require('./passport-config')
initializePassport(
  passport,
  email => {
    return User.findOne({ email: email }).exec()
  },
  id => {
    return User.findById(id).exec()
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

app.get('/', checkAuthenticated, async (req, res) => {
  console.log('Handling GET request to /');

  try {
    const userId = req.session.userId;
    console.log('User ID from session:', userId);

    // Assuming you're using a database library like Mongoose to query the database
    const user = await User.findById(userId).exec();

    if (user) {
      // User found, you can access the user's name
      const userName = user.name;
      console.log('User name:', userName);

      // Render the view with the user's name
      res.render('index.ejs', { name: userName });
    } else {
      // User not found
      console.log('User not found');
      res.send('User not found');
    }
  } catch (err) {
    // Handle any errors that occur during the database query or rendering
    console.error('An error occurred:', err);
    res.status(500).send('An error occurred');
  }
});




//Lets Check if there is an active session
app.get('/check-session', (req, res) => {
  if (req.session && req.session.userId) {
    // A session exists, and you have a user ID stored in the session
    res.send('Session exists with user ID: ' + req.session.userId)
  } else {
    // No session exists or the session does not contain a user ID
    res.send('No active session')
  }
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
    console.log('User is authenticated');
    return next()
  }

  console.log('User is not authenticated, redirecting to /login');
  res.redirect('/login')
}


function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    console.log('User is authenticated, redirecting to /')
    return res.redirect('/')
  }
  console.log('User is not authenticated')
  next()
}

app.listen(3000)