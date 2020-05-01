const express = require('express');
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passportConfig = require("../passport");
const passport = require("passport");
const secretKey = require("../config/keys").jwtKey;
const User = require('../models/user_model')


const validateLogin = require("../validation/login-validation");
const validateRegister = require("../validation/register-validation");

const LogValidationMiddleware = (req,res,next) =>{
    const {errors,isValid} = validateLogin(req.body);
    if (!isValid) return res.status(400).json(errors);
    next();
}

const RegValidationMiddleware = (req,res,next) =>{
    const {errors,isValid} = validateRegister(req.body);
    if (!isValid) return res.status(400).json(errors);
    next();
}


const signToken = userId => {
    return jwt.sign({
        iss: secretKey,
        sub:userId
    }, secretKey, {
        expiresIn: "3600000"
    });
}


//----------------------------------------Router----------------------------------------

router.get('/info',passport.authenticate('jwt',{session : false}),(req,res)=>{
    const {username,isAdmin} = req.user;
    res.json({username,isAdmin});
})

router.post('/login',LogValidationMiddleware,passport.authenticate('local',{session : false}),(req,res)=>{
    if(req.user.error) return res.status(400).json(req.user.errors);
    if(req.isAuthenticated()){
       const {_id,username,isAdmin} = req.user;
       const token = signToken(_id);
       res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
       res.json({username,isAdmin});
    }
});

router.post("/register",RegValidationMiddleware,(req, res) => {
    User.findOne({mail: req.body.mail}).then(user => {
        if (user) return res.status(400).json({mail: "User already exists"});
        else {
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(req.body.pass, salt, (err, hash) => {
                    if (err) throw err;

                    const newUser = new User({
                        username: req.body.login,
                        mail: req.body.mail,
                        password: hash
                    });
                    newUser.save()
                        .then(createdUser => {
                            const token = signToken(createdUser._id);
                            res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
                            res.status(200).json({username:createdUser.username,isAdmin:0});
                        })
                        .catch(err => console.log(err));
                });
            });
        }
    });
});

router.get('/logout',passport.authenticate('jwt',{session : false}),(req,res)=>{
    res.clearCookie('access_token');
    res.json({success:true})
});



//-------------------------------------Socials------------------------------------






router.get('/github',
  (passport.authenticate('github')));

router.get('/github/callback',passport.authenticate('github',{failureRedirect:"/login"}),function(req, res) {
    const {_id} = req.user;
    const token = signToken(_id);
    res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
    res.redirect('/');
});




router.get('/twitter',
  (passport.authenticate('twitter')));

router.get('/twitter/callback',passport.authenticate('twitter',{failureRedirect:"/login"}),function(req, res) {
    const {_id} = req.user;
    const token = signToken(_id);
    res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
    res.redirect('/');
});



router.get('/facebook',
  (passport.authenticate('facebook')));

router.get('/facebook/callback',passport.authenticate('facebook',{failureRedirect:"/login"}),function(req, res) {
    const {_id} = req.user;
    const token = signToken(_id);
    res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
    res.redirect('/');
});



router.get('/google',
  (passport.authenticate('google')));

router.get('/google/callback',passport.authenticate('google',{failureRedirect:"/login"}),function(req, res) {
    const {_id} = req.user;
    const token = signToken(_id);
    res.cookie('access_token',token,{httpOnly: true, sameSite:true}); 
    res.redirect('/');
});






//-------------------------------------Export-------------------------------------

module.exports = router;




