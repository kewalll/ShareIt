import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import nodemailer from "nodemailer";
import mongoose from "mongoose";
import otpGenerator from "otp-generator";

const app = express();
const port = 3000;
const saltrounds = 10;
env.config()

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000*60*60*24,
    }
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO, {
}).then(() => console.log("MongoDb connected successfully!"))
.catch((err) => console.log(err));

const User = mongoose.model("User", {
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
});

const Post = mongoose.model("Post", {
    topic: {
        type: String,
        required: true,
    },
    thought: {
        type: String,
        required: true,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});


app.get("/", (req,res) => {
    res.render("landingpage.ejs");
})

app.get("/otpverification", (req,res) => {
    res.render("otpverification.ejs");
})

app.get("/login", (req,res) => {
    res.render("login.ejs");
})

app.get("/home", async (req,res) => {
    if(req.isAuthenticated()){
        const posts = await Post.find().populate('user').sort({ createdAt: -1 });
        res.render("home.ejs", {user: req.user, posts: posts});
    } else{
        res.redirect("/login");
    }
})

app.get("/about", (req,res) => {
    if(req.isAuthenticated()){
        res.render("about.ejs", {user: req.user});
    } else{
        res.redirect("/login");
    }
})

app.get("/mypost", async (req,res) => {
    if(req.isAuthenticated()){
        const curruser = req.user;
        const posts = await Post.find({user: curruser._id}).populate('user').sort({ createdAt: -1 });
        res.render("mypost.ejs", {user: req.user, posts: posts});
    } else{
        res.redirect("/login");
    }
})

app.get("/create", (req,res) => {
    if(req.isAuthenticated()){
        res.render("create.ejs", {user: req.user});
    } else{
        res.redirect("/login");
    }
})

app.post("/create", async(req,res) => {
    if(req.isAuthenticated()){
        const topic = req.body.topic;
        const thought = req.body.thought;
        const user = req.user;
        try{
            const post = new Post({
            topic: topic,
            thought: thought,
            user:user._id,
            })
            await post.save();
        } catch(err){
            console.log(err);
        }
        res.render("create.ejs");
    } else{
        res.redirect("/login");
    }
})

app.get("/signup", (req,res) => {
    res.render("signup.ejs");
})

app.post("/signup", async (req,res) => {
    const email = req.body.username;
    const password = req.body.password;
    const firstname = req.body.firstname;
    const lastname = req.body.lastname;
    if(!email || !password || !firstname || !lastname){
        return res.render("signup.ejs");
    }
    try{
        const user = await User.findOne({ email });
        console.log(user);
        if(user){
            return res.redirect("/login");
        } else{
            const otp = otpGenerator.generate(6, {
                digits: true,
            })
            try{
                let transporter = nodemailer.createTransport({
                    host: "smtp.gmail.com",
                    port: 587,
                    secure: false,
                    auth: {
                        user: "kewal210504@gmail.com",
                        pass: process.env.NODEMAILER,
                    },
                    debug: true,
                });
                let info = await transporter.sendMail({
                    from: "kewal210504@gmail.com",
                    to: email,
                    subject: "OTP for SignUp",
                    text: `Your OTP for signup is: ${otp}`,
                });
                console.log("Email sent:", info.response);
            } catch(err){
                console.log("ERROR sending Mail: ",err);
            }
            req.session.username = email;
            req.session.password = password;
            req.session.firstname = firstname;
            req.session.lastname = lastname;
            req.session.otp = otp;
            res.redirect("/otpverification");
        }
    } catch(err){
        console.log(err);
    }
});

app.post("/verifyotp", async (req,res) => {
    const enteredOTP = req.body.otp;
    if(enteredOTP == req.session.otp){
        const firstName = req.session.firstname;
        const lastName = req.session.lastname;
        const email = req.session.username;
        const hashedPass = await bcrypt.hash(req.session.password,10);
        try{
            const user = new User({
                firstName,
                lastName,
                email,
                password: hashedPass,
            });
            await user.save();
            req.login(user, (err) => {
                console.log(err);
                res.redirect("/about");
              });
        } catch(err){
            console.log(err);
        }
    } else{
        res.render("otpverification.ejs");
    }
})

app.post("/login", passport.authenticate("local",{
    successRedirect: "/about",
    failureRedirect: "/login"
}))

app.get("/logout", (req,res) => {
    req.logout(function(err){
        if (err){
            return next(err);
        }
        res.redirect("/");
    })
})

passport.use(new Strategy(async function verify(username, password, cb){
    const email = username;
    try{
        const user = await User.findOne({ email });
        if(user){
            bcrypt.compare(password, user.password, (err, res) => {
                if(err){
                    return cb(err);
                } else{
                    if(res){
                        cb(null, user);
                    } else{
                        cb(null, false);
                    }
                }
            });
        } else {
            return cb(null, false);
        }
    } catch(err){
        console.log(err);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null,user);
})

passport.deserializeUser((user, cb) => {
    cb(null,user);
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});