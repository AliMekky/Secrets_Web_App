//jshint esversion:6

////////////requiring pachages/////////////////
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const request = require("request");
const mongoose = require("mongoose");
const ejs = require("ejs");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;


const app = express();

//////////////using pachages/////////////////
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended : true}));
app.set('view engine','ejs');


app.use(session({
  secret : "Our little secret.",
  resave : false,
  saveUninitialized : false,
  cookie: {secure : false}
}));
app.use(passport.initialize());
app.use(passport.session());

//database connections and schemas///////////////////
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = mongoose.Schema({
  email : String,
  password : String,
  googleId : String,
  facebookId : String,
  secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user",userSchema);
passport.use(User.createStrategy());

//may cause an error if we use another strategy rather than the "local" startegy
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


passport.serializeUser(function(user, done){
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err, user);
  });
});



//////////SHOULD BE IN THIS PLACE //////////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrl : "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id , username: profile.emails[0].value}, function (err, user) {
      return cb(err, user);
    });
  }
));
//////SHOULD BE IN THIS PLACE/////////////


////SHOULD BE IN THIS PLACE////////////////
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
////////SHOULD BE IN THIS PLACE/////////////


/////////////////////get certain route///////////////
app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req, res){
  User.find({"secret" : {$ne : null}},function(err,foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets : foundUsers});
      }
    }
  })
});

app.get("/logout", function(req, res){
  req.logout(function(err){});
  res.redirect("/");
});

app.get("/submit",function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});


app.get("/auth/google",passport.authenticate("google", {scope : ["profile","email"]}));

app.get("/auth/google/secrets", //where google will send back the info.
    passport.authenticate("google",{ failureRedirect : "/login"}),
    function(req, res){
      res.redirect("/secrets");
    });

app.get('/auth/facebook',
  passport.authenticate('facebook', {scope : "public_profile"}));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });




///////////////post certain route////////////////


app.post("/register",function(req,res){

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash){
  //   const newUser = new User({
  //     email : req.body.username,
  //     password : hash
  //   })
  //   newUser.save(function(err){
  //     if(!err){
  //       res.render("secrets");
  //     }
  //     else{
  //       console.log(err);
  //     }
  //   });
  // });

  User.register({username : req.body.username}, req.body.password, function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req, res, function(){
        //successful authentication and we managed to set up a cookie that saved the user current logged in session
        res.redirect("/secrets");
      });
    }
  })
});


app.post("/login",function(req,res){
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email : username},function(err,foundUser){
  //   if(!err){
  //     if(foundUser){
  //       bcrypt.compare(password, foundUser.password, function(err, result){
  //         if(result === true){
  //           res.render("secrets");
  //         }
  //       })
  //       }
  //       else{
  //         console.log(err);
  //       }
  //     }
  //
  // })

  const user = new User({
    username : req.body.username,
    password : req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    }
    else{
        passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      });
    }
  });

});


app.post("/submit",function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }

  });
});






app.listen(3000,function(){
  console.log("Running");
})
