const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
var GitHubStrategy = require('passport-github').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('./models/user_model');


const cookieExtractor = req => {
    let token = null;
    if(req && req.cookies) token = req.cookies['access_token'];
    return token;
}

passport.use(new LocalStrategy((username,password,done)=>{
    User.findOne({$or:[{'username':username},{'mail':username}]},(err,user)=>{
        if(err) return done(err);
        if(!user) return done(null,{errors:{mail: "User not found"},error:true});
        user.comparePassword(password,done); 
    })
}))

passport.use(new JwtStrategy({jwtFromRequest:cookieExtractor,secretOrKey:"kaboo"}, (payload,done)=>{
    User.findById({_id:payload.sub},(err,user)=>{
        if(err) return done(err,false);
        if(user) return done(null,user);
        return done(null,false);
    })
}))







passport.use(new GitHubStrategy({
    clientID: '08ef72ed0e69ffd7cf1a',
    clientSecret: 'f0eefb55622b8663a845be0d0a04e8eb4a3fb6f2',
    callbackURL: "/user/github/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    let {login,email}=profile._json
    if(email === null) return done(null, false, { error:true })

    User.findOne({'mail':email},(err,user)=>{
        if(err) return done(err);
        if(user)return done(null,user)
        else{
            const newUser = new User({username:login,mail:email,password:'social'});
            newUser.save().then(createdUser=> done(null,createdUser))
                          .catch(err => {console.log(err)})
        }
    })
  }
));

passport.use(new GoogleStrategy({
    clientID: '1033091184223-f3a367k9fj16m63l3tjqf8o8sahu2alo.apps.googleusercontent.com',
    clientSecret: 'h5AfooMfYo5lvT4gi7T7SDTA',
    callbackURL: "/user/google/callback",
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile);

    const login = profile._json.name;
    const email = profile._json.email;
    if(email === null) return done(null, false, { error:true })

    User.findOne({'mail':email},(err,user)=>{
        if(err) return done(err);
        if(user)return done(null,user)
        else{
            const newUser = new User({username:login,mail:email,password:'social'});
            newUser.save().then(createdUser=> done(null,createdUser))
                          .catch(err => {console.log(err)})
        }
    })
  }
));

passport.use(new TwitterStrategy({
  consumerKey: 'W7VI3RuOTXwt7bFWagx0nUKXe',
  consumerSecret: 'wGwWPCIGl4O9Sc4Bcla6OcRMkGWm9xEzOSNsAch2A83SwR3qII',
  callbackURL: "/user/twitter/callback",
  includeEmail: true
},
function(accessToken, refreshToken, profile, done) {
  console.log(profile);

  let login = profile._json.name;
  const email = "Nomail"

  User.findOne({'username':login},(err,user)=>{
      if(err) return done(err);
      if(user)return done(null,user)
      else{
          const newUser = new User({username:login,mail:email,password:'social'});
          newUser.save().then(createdUser=> done(null,createdUser))
                        .catch(err => {console.log(err)})
      }
  })
}
));

// passport.use(new FacebookStrategy({
//   clientID: '2335655800048641',
//   clientSecret: '5c77ae2592dbae2f1aa19477dcb99f84',
//   callbackURL: "/user/facebook/callback",
// },
// function(accessToken, refreshToken, profile, done) {
//   console.log(profile);

//   let email = profile.emails[0].value;
//   let login = profile.displayName;
//   if(email === null) return done(null, false, { error:true })

//   User.findOne({'mail':email},(err,user)=>{
//       if(err) return done(err);
//       if(user)return done(null,user)
//       else{
//           const newUser = new User({username:login,mail:email,password:'social'});
//           newUser.save().then(createdUser=> done(null,createdUser))
//                         .catch(err => {console.log(err)})
//       }
//   })
// }
// ));



passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((user,done)=>done(null,user));
