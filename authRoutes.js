const router = require("express").Router();
const User = require("./User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const createAccess = (id)=> jwt.sign({id},process.env.JWT_ACCESS_SECRET,{expiresIn:"15m"});
const createRefresh = (id)=> jwt.sign({id},process.env.JWT_REFRESH_SECRET,{expiresIn:"7d"});


// REGISTER
router.post("/register", async(req,res)=>{
  const {username,email,password} = req.body;

  if(await User.findOne({email}))
    return res.status(400).json({msg:"Email exists"});

  const hash = await bcrypt.hash(password,12);
  const user = await User.create({username,email,password:hash});

  res.json({msg:"Account created"});
});


// LOGIN
router.post("/login", async(req,res)=>{
  const {email,password} = req.body;
  const user = await User.findOne({email});
  if(!user) return res.status(404).json({msg:"User not found"});

  const ok = await bcrypt.compare(password,user.password);
  if(!ok) return res.status(401).json({msg:"Wrong password"});

  const accessToken = createAccess(user._id);
  const refreshToken = createRefresh(user._id);

  user.refreshToken = refreshToken;
  await user.save();

  res.cookie("refreshToken",refreshToken,{
    httpOnly:true,
    secure:false,
    sameSite:"strict",
    maxAge:7*24*60*60*1000
  });

  res.json({accessToken});
});


// REFRESH TOKEN
router.post("/refresh", async(req,res)=>{
  const token = req.cookies.refreshToken;
  if(!token) return res.status(401).json({msg:"No refresh token"});

  try{
    const decoded = jwt.verify(token,process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if(user.refreshToken !== token)
      return res.status(403).json({msg:"Token mismatch"});

    res.json({accessToken:createAccess(user._id)});
  }catch{
    res.status(403).json({msg:"Invalid refresh"});
  }
});


// LOGOUT
router.post("/logout", async(req,res)=>{
  const token = req.cookies.refreshToken;
  if(token){
    const decoded = jwt.decode(token);
    if(decoded) await User.findByIdAndUpdate(decoded.id,{refreshToken:null});
  }
  res.clearCookie("refreshToken");
  res.json({msg:"Logged out"});
});

module.exports = router;
