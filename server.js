const express = require('express');
const cors = require('cors');
const mysql= require('mysql2');
const bcrypt= require('bcrypt');
const jwt= require('jsonwebtoken');
const app = express();

app.use(express.static('public'));
app.use(express.json());
app.use(cors());
const port = 3000;
const JWT_SECRET = "mysecret_key";


const db= mysql.createConnection({
  host:"localhost",
  user:"root",
  password:"Navysql@1234",
  database:"LOGINPAGE"
});

db.connect(err=>{
  if(err){
    console.log("failed",err);
    return;
  }
  console.log("sucess");
});

app.get("/test-db",(req,res)=>{
  db.query("SELECT 1", (err,result) => {
    if(err) return res.status(500).send(err);
    res.send(result);
  });
});


app.post("/register",async (req,res)=>{
  const {email,password}= req.body;
  if(!email || !password){
    return res.status(400).json({error: "missing field"});
  }
  try{
    const hashpwassword= await bcrypt.hash(password,10);
    db.query("INSERT INTO users (email,password) VALUES (?,?)",
    [email,hashpwassword],
    (err,result)=>{
      if(err) return res.status(500).json({error:"user may already exist"});
      res.status(201).json({message:"user registered"});
    });
  }catch(err){
    res.status(500).json({error:"server error"});
  }
});



app.post("/login",(req,res)=>{
  const {email,password}= req.body;
  if(!email || !password){
    return res.status(400).json({error:"empty"});
  }
  db.query(
    "SELECT * FROM users WHERE email=?",
    [email],
    async(err,result)=>{
      if(err) return res.status(500).json({error:"server error"});
      if(result.length===0) return res.status(401).json({error:"authN error"});
      const user=result[0];
      const match= await bcrypt.compare(password,user.password);
      if(!match) return res.status(401).json({error:"inavalid pass"});
      const token= jwt.sign(
        {id:user.id, email: user.email},
        JWT_SECRET,
        {expiresIn:"1h"}
      );
      res.json({token});
    }
  );
});


function auth (req,res,next){
  const header= req.headers["authorization"];
  const token= header && header.split(" ")[1];

  if(!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err,user)=>{
    if(err) return res.sendStatus(403);
    req.user=user;
    next();
  });
}
app.get("/dashboard",auth,(req,res,)=>{
  res.json({user:req.user});
});



app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});