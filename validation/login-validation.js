const Validator = require("validator");
const isEmpty = require("is-empty");

module.exports = function validateLogin(data) {
    let errors = {};


    data.username = !isEmpty(data.username)
        ? data.username
        : "";
    data.password = !isEmpty(data.password) 
        ? data.password
        : "";

    if (Validator.isEmpty(data.username)) 
        errors.mail = "Email field is required";
    // else if (!Validator.isEmail(data.username)) 
    //     errors.mail = "Email is invalid";
    
    if (Validator.isEmpty(data.password)) 
        errors.pass = "Password field is required";
    
    return {errors, isValid: isEmpty(errors)};
};