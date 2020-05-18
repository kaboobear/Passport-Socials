const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt')

const UserSchema = new Schema({
    username:{
        type:String,
        required:true
    },
    mail:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    isAdmin:{
        type:Number,
        required:true,
        default:0
    }
},{timestamps:true});

UserSchema.methods.comparePassword = function(password,cb){
    bcrypt.compare(password,this.password,(err,isMatch)=>{
        if(err)return cb(err);
        else{
            if(!isMatch) return cb(null,isMatch);
            return cb(null,this);
        }
    })
}

module.exports = mongoose.model("User",UserSchema);



// UserSchema.pre('save',function(next){
//     if(!this.isModified('password')) return next();
//     bcrypt.hash(this.password,10,(err,hash)=>{
//         if(err) return next(err);
//         this.password = hash;
//         next();
//     })
// })