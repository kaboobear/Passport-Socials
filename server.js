const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const passport = require("passport");
const db = require("./config/keys").mongoURI;
const https = require('https');
const fs = require('fs');


const user_route = require("./routes/user_route");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(session({secret:'kaboo',resave:true,saveUninitialized:true}))
app.use(passport.initialize());
app.use(passport.session());



mongoose
    .connect(db,{ useNewUrlParser: true,useUnifiedTopology: true,useCreateIndex:true })
    .then(()=>{console.log("MongoDb was connected")})
    .catch((err)=>{console.log(err);})

app.use('/user',user_route);

if(process.env.NODE_ENV === 'production'){
    app.use(express.static('client/build'));

    app.get("*",(req,res)=>{
        res.sendFile(path.resolve(__dirname,'client','build','index.html'));
    })
}

app.listen(port,()=>{console.log(`Server started on port ${port}`)}) 
