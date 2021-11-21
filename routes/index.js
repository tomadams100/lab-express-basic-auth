const express = require('express');
const router = require("express").Router();
const User = require('../models/User.model');
const saltRound = 5;
const bcrypt = require('bcrypt');

router.route("/login")
.get((req,res)=>{
  res.render("login")
})
.post((req,res)=>{
	const {username,password} = req.body
	if(!username||!password) res.render('login',{errorMessage:"Username/password not provided."})
	User.findOne({username})
	.then((user)=>{
		if(!user) res.render('login',{errorMessage:"Username does not exist."})
		const isPwdCorrect = bcrypt.compareSync(password,user.password)
		if(isPwdCorrect) {
			req.session.loggedInUser = user
			res.render("user-profile")
		} 
		else res.render('login',{errorMessage:"Username/password incorrect."})
	})
})

router.route("/register")
.get((req,res)=>{
  res.render("register")
})
.post((req,res)=>{
  const {username,password} = req.body
  if(!username||!password) res.render('register')
  User.findOne({username})
  .then((user)=>{
    if(user) res.render('register',{errorMessage:"User exists."})
		
		const salt = bcrypt.genSaltSync(saltRound)
		const hashedPwd = bcrypt.hashSync(password,salt)
		
		User.create({username,password:hashedPwd})
		.then((req,res)=>res.render("user-profile"))
		.catch((err)=>res.render("register",{errorMessage: "Database broken"}))
  })
})

router.get('/logout', (req, res) => {
	req.session.destroy((err) => {
		if (err) res.redirect('/');
		else res.redirect('/');
	});
});

function isLoggedIn(req,res,next) {
	if(req.session.loggedInUser) next()
	else res.redirect("/")
}

router.get("/private",isLoggedIn, (req,res)=>{
	res.render("private")
})

router.get("/main", (req,res)=>{
	res.render("main")
})

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

module.exports = router;
