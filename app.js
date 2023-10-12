//jshint esversion:6
require('dotenv').config()
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use(session({
  secret: "this is my secret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect(process.env.MONGO_DATA);
mongoose.set("useCreateIndex", true);
const secretSchema = new mongoose.Schema({
  secretString: String
});
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: false
  },
  password: String,
  googleId: String,
  facebookId: String,
  secret: [{
    type: secretSchema
  }]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const Secret = mongoose.model("Secret", secretSchema);
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://damp-brushlands-35802.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FB_APP_ID,
    clientSecret: process.env.FB_APP_SECRET,
    callbackURL: "https://damp-brushlands-35802.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.listen(process.env.PORT || 3000, function() {
  console.log("Server is up and running");
});
app.get("/", function(req, res) {
  res.render("home");
});
app.get('/auth/facebook',
  passport.authenticate('facebook'));
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  }));


app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register", function(req, res) {
  res.render("register", {
    errorString: ""
  });
});
app.get("/login", function(req, res) {
  res.render("login", {
    errorString: ""
  });
});
app.get("/login/failedlogin", function(req, res) {
  res.render("login", {
    errorString: "Your username or password or invalid"
  });
});
app.get("/secrets", function(req, res) {
  console.log(req);
  if(req.isAuthenticated()){

    User.find({
      "secret": {
        $ne: null
      }
    }, function(err, found) {
      if (!err) {

        res.render("secrets", {
          userSecrets: found,
          currentID: req.user._id
        });
      }
    });
  }else{
    res.redirect("/login");
  }

});

app.post("/register", function(req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      res.render("register", {
        errorString: err.message
      });
    } else {
      passport.authenticate("local", {
        failureRedirect: '/login'
      })(req, res, function() {

        res.redirect("/login");
      });
    }
  });



});
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});
app.post("/login", function(req, res) {
  const user = new User({
    email: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (err) {
      console.log(err);

    } else {

      passport.authenticate("local", {
        failureRedirect: '/login/failedlogin'
      })(req, res, function() {

        res.redirect("/secrets");

      });
    }
  });
});
app.get("/submit", function(req, res) {
  res.render("submit");
});
app.post("/submit", function(req, res) {
  var secret = req.body.secret;
  var secrets = new Secret({
    secretString: secret
  });
  secrets.save();
  User.findById(req.user.id, function(err, found) {
    if (!err) {
      if (found) {

        found.secret.push(secrets);
        found.save();
        res.redirect("/secrets");
      }
    }
  });
});
app.post("/delete", function(req, res) {
  var userSecret = req.body.checkbox;
  var userID = req.body.userID;
  User.findOneAndUpdate({
    _id: userID
  }, {
    $pull: {
      secret: {
        _id: userSecret
      }
    }
  }, function(err) {
    if (!err) {
      res.redirect("/secrets");
    }
  })
});
