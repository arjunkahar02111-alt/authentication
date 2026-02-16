require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const connectDB = require("./db");
const authRoutes = require("./authRoutes");
const protect = require("./authMiddleware");

const app = express();
connectDB();

app.use(helmet());
app.use(cors({origin:true,credentials:true}));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({windowMs:60*1000,max:100}));

app.use("/api/auth",authRoutes);

app.get("/api/private",protect,(req,res)=>{
  res.json({msg:"Welcome authenticated user",user:req.user});
});

app.listen(process.env.PORT,()=>console.log("API running"));
