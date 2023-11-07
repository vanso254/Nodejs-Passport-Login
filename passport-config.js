const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const User = require('./userModels');


async function getUserPassword(email) {
  const user = await User.findOne({ email: email });
  return user ? user.password : null;
}

function initialize(passport, getUserByEmail, getUserById) {
  const authenticateUser = async (email, password, done) => {
    const hashedPassword = await getUserPassword(email);

    if (!hashedPassword) {
      return done(null, false, { message: 'No user with that email' });
    }

    try {
      if (await bcrypt.compare(password, hashedPassword)) {
        const user = getUserByEmail(email);
        return done(null, user);
      } else {
        return done(null, false, { message: 'Password incorrect' });
      }
    } catch (e) {
      return done(e);
    }
  }

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))

  passport.serializeUser((user, done) => {
    // Store the user's ID and email in the session
    const sessionData = {
      id: user.id,
      email: user.email
    };
    done(null, sessionData);
  });
  
  
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  })
}

module.exports = initialize
