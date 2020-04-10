const express = require('express');
const app = express();
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

//middlewares
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: 'I am najam',
    resave: true,
    saveUninitialized: true,
  })
);
app.set('view engine', 'ejs');

//connect to database
mongoose.connect('mongodb://localhost:27017/learning_auth', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//create user model
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
const User = mongoose.model('User', userSchema);

//Passport Configuration
const options = {
  usernameField: 'email',
};
const Strategy = new LocalStrategy(options, (email, password, done) => {
  //Find User
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return done(null, false);
      }
      //match password
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      });
    })
    .catch((err) => console.log(err));
});
passport.serializeUser((id, done) => {
  done(null, id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

passport.use(Strategy);
app.use(passport.initialize());
app.use(passport.session());

//routes
app.get('/', (req, res) => {
  res.render('home');
});
app.get('/login', (req, res) => {
  res.render('login');
});
app.get('/winner', (req, res) => {
  res.render('winner');
});
app.post('/register', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) throw err;
      User.create({
        email: email,
        password: hash,
      });
    });
  });
  res.redirect('/login');
});
app.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/winner',
    failureRedirect: '/login',
  })(req, res, next);
});
app.listen(3000, () => console.log('server has started!!!'));
