const jwt = require("jsonwebtoken");

module.exports = (req,res,next)=>{
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({msg:"No token"});

  const token = auth.split(" ")[1];

  try{
    const decoded = jwt.verify(token,process.env.JWT_ACCESS_SECRET);
    req.user = decoded;
    next();
  }catch{
    res.status(403).json({msg:"Invalid/Expired token"});
  }
};
