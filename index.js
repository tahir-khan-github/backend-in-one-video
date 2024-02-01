import  express  from "express";
import path from "path"
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

//server creation
const app = express(); 

//database connection
mongoose.connect("mongodb://localhost:27017",{
  dbName:"backend",
})
.then(()=> console.log("db connected"))
.catch((e) => console.log(e))  

//schema creation for datatypes
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
})

//modal creation to store values in database
const User = mongoose.model("User",userSchema)



//middleware
app.use(express.static(path.join(path.resolve(),"public")));//to use the static files globally
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());//to use cookies

app.set("view engine","ejs");//for views

//handler to check for authentication
const isAuthenticated = async (req,res,next) =>{  
  const {token} = req.cookies;
  if(token){
    const decode = jwt.verify(token,"abcdef") //will give back original id

    req.user = await User.findById(decode._id); // if user exist storing it

    next();
  }else{
    res.render("register"); // default page
  }
}

//defalut route , if handler works then go to logout
app.get("/",isAuthenticated,(req,res)=>{
   res.render("logout",{name: req.user.name});
})

app.get("/login",(req,res)=>{
   res.render("login");
})

//form submission
app.post("/login", async (req,res)=>{
  const {email, password} = req.body;

  let user = await User.findOne({email});

  if(!user){
    return res.redirect("/register");
  }

  const isMatch = await bcrypt.compare(password,user.password);

  if(!isMatch) return res.render("login",{email ,message: "Incorrect Password"});

  const token = jwt.sign({_id: user._id},"abcdef") //will decode user id

  res.cookie("token",token,{
    expires: new Date(Date.now()+ 60*1000),
    httpOnly: true
  });
  res.redirect("/");
})
//form submission
app.post("/register", async (req,res)=>{
  const {name, email, password} = req.body;

  let user = await User.findOne({email});

  if(user){ // if user already exist go to login
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password,10); //password hashing

   user = await User.create({ //adding into database
    name,
    email,
    password: hashedPassword
  })

  const token = jwt.sign({_id: user._id},"abcdef") //will decode user id

  res.cookie("token",token,{  //setting user id in cookies
    expires: new Date(Date.now()+ 60*1000),
    httpOnly: true
  });
  res.redirect("/");
})

//logout and clear cookie
app.get("/logout", async (req,res)=>{
  res.cookie("token",null,
  {
    expires: new Date(Date.now()),
    httpOnly: true
  });
  res.redirect("/");
})


app.listen(5000,()=>{
    console.log("server is working")
})