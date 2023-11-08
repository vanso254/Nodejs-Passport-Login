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
      console.log('User authentication failed: No user with that email');
      return done(null, false, { message: 'No user with that email' });
    }

    try {
      if (await bcrypt.compare(password, hashedPassword)) {
        const user = getUserByEmail(email);
        console.log('User authentication succeeded:', user.email);
        return done(null, user);
      } else {
        console.log('User authentication failed: Password incorrect');
        return done(null, false, { message: 'Password incorrect' });
      }
    } catch (e) {
      console.log('User authentication failed: An error occurred');
      return done(e);
    }
  }

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))

  passport.serializeUser((user, done) => {
    // Store the user's ID and email in the session
    const sessionData = {
      id: user.id,
      email: user.email
    }
    console.log('User serialized:', user.email)
    done(null, sessionData);
  })
  
  
  passport.deserializeUser((id, done) => {
    const user = getUserById(id);
    if (user) {
      console.log('User deserialized:', user.email);
    } else {
      console.log('User deserialization failed: User not found');
    }
    return done(null, user);
  })
}

module.exports = initialize
