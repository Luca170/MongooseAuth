const express= require("express")
const session = require("express-session")
const passport = require("passport")
const bcrypt = require("bcrypt")
const ObjectId = require('mongodb').ObjectId;
const mongoose = require("mongoose")
const LocalStrategy = require("passport-local")
const app = express()

const URI = "mongodb+srv://ciao:ciao@cluster0.ogg8o.mongodb.net/mydb?retryWrites=true&w=majority" ;
mongoose.connect(URI, {useNewUrlParser:true, useUnifiedTopology:true})
app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(session({
    secret:"Your secret key",
    resave:true,
    saveUninitialized:true,
    cookie:{secure:false}
}))
app.use(express.urlencoded({extended:false}))
app.use(express.json())
const userSchema = new mongoose.Schema({
    username:String,
    password:String
}, {collection:"User"})
let User = mongoose.model("User", userSchema)
app.use(passport.initialize())
app.use(passport.session())
passport.serializeUser(((user,done) => {
    done(null,user._id)
}))
passport.deserializeUser((id, done) => {
    User.findOne({ _id: new ObjectId(id) }, (err, doc) => {
      if (err) return console.error(err);
      done(null, doc);
    });
  });
function ensureAuthenticated(req,res,next) {
 if(!req.isAuthenticated()) {
    res.redirect("/login")
 }
 next()
}
passport.use(new LocalStrategy(
    function (username, password, done) {
     User.findOne({ username: username }, function (err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        if (!bcrypt.compareSync(password, user.password)) { 
          return done(null, false);
        }
        return done(null, user);
      });
    }
  ));
app.get("/", (req,res) => {
    res.render("home.ejs")
})
app.get("/login", (req,res) => {
    res.render("login.ejs")
})
app.get("/register", (req,res) => {
    res.render("register.ejs")
})
app.post("/rreq", (req,res,next) => {
   const hash = bcrypt.hashSync(req.body.password,12)
   let new_User = new User({
       username: req.body.username,
       password:hash
   })
   User.findOne({username:req.body.username}, (err,user) => {
       if(err){
           next(err)
       }
       else if(user) {
           res.send("User already exists")
       }
       else {
           new_User.save((err,doc) => {
               if(err) throw err
               console.log(doc)
               res.redirect("/")
           })
       }
   })
})
app.post("/lreq",passport.authenticate("local", {failureRedirect:"/login"}), (req,res) => {
    res.redirect("/logged")
})
app.get("/logged", ensureAuthenticated, (req,res) => {
    res.render("logged.ejs")
})
app.post("/logout", (req,res) => {
     req.logout()
     res.redirect("/")
     })
app.listen(8000)