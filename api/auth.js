const express=require("express"),cors=require("cors"),mongoose=require("mongoose"),crypto=require("crypto");

const app=express();
app.use(cors());
app.use(express.json({limit:"1mb"}));

const User=mongoose.models.User||mongoose.model("User",new mongoose.Schema({
  email:{type:String,unique:true,lowercase:true,trim:true},
  passwordHash:String,
  salt:String,
  plan:{type:String,default:"free"},
  createdAt:{type:Date,default:Date.now}
}));

let dbPromise=null;
async function db(){
  if(!process.env.MONGODB_URI) throw new Error("Database is not configured. Add MONGODB_URI to the Vercel project environment variables.");
  if(mongoose.connection.readyState===1) return;
  if(!dbPromise){
    dbPromise=mongoose.connect(process.env.MONGODB_URI,{
      serverSelectionTimeoutMS:8000,
      connectTimeoutMS:8000,
      maxPoolSize:5
    }).catch(err=>{dbPromise=null;throw err});
  }
  await dbPromise;
}

function hash(password,salt){return crypto.scryptSync(password,salt,64).toString("hex")}
function makeToken(user){
  if(!process.env.JWT_SECRET) throw new Error("Authentication is not configured. Add JWT_SECRET to the Vercel project environment variables.");
  const h=Buffer.from(JSON.stringify({alg:"HS256",typ:"JWT"})).toString("base64url");
  const p=Buffer.from(JSON.stringify({sub:String(user._id),email:user.email,plan:user.plan,exp:Date.now()+604800000})).toString("base64url");
  const s=crypto.createHmac("sha256",process.env.JWT_SECRET).update(h+"."+p).digest("base64url");
  return h+"."+p+"."+s;
}
function verify(token){
  try{
    if(!process.env.JWT_SECRET)return null;
    const [a,b,s]=String(token||"").split(".");
    if(!a||!b||!s)return null;
    const expected=crypto.createHmac("sha256",process.env.JWT_SECRET).update(a+"."+b).digest("base64url");
    if(s.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(expected)))return null;
    const payload=JSON.parse(Buffer.from(b,"base64url").toString());
    return payload.exp>Date.now()?payload:null;
  }catch{return null}
}
function safeError(error,fallback){
  if(error?.code==="ENOTFOUND"||error?.name==="MongooseServerSelectionError") return "Database connection failed. Check MONGODB_URI and MongoDB Atlas network access.";
  if(error?.code==="ECONNREFUSED"||error?.name==="MongoNetworkError") return "Database connection was refused. Check MongoDB Atlas availability and network access.";
  return error?.message||fallback;
}
async function requireAuth(req,res,next){
  const payload=verify((req.headers.authorization||"").replace(/^Bearer\s+/i,""));
  if(!payload)return res.status(401).json({error:"Authentication required"});
  req.auth=payload;next();
}

app.get("/api/auth/health",async(req,res)=>{
  try{
    await db();
    res.json({ok:true,database:"connected"});
  }catch(error){
    res.status(503).json({ok:false,database:"unavailable",error:safeError(error,"Authentication service unavailable")});
  }
});

app.post("/api/auth/register",async(req,res)=>{
  try{
    const email=String(req.body?.email||"").trim().toLowerCase();
    const password=String(req.body?.password||"");
    if(!/^\S+@\S+\.\S+$/.test(email)||password.length<8)
      return res.status(400).json({error:"Use a valid email and password of at least 8 characters"});
    await db();
    if(await User.exists({email}))return res.status(409).json({error:"Account already exists"});
    const salt=crypto.randomBytes(16).toString("hex");
    const user=await User.create({email,salt,passwordHash:hash(password,salt)});
    res.status(201).json({token:makeToken(user),user:{id:String(user._id),email:user.email,plan:user.plan}});
  }catch(error){
    const message=safeError(error,"Registration failed");
    res.status(message.startsWith("Database")||message.startsWith("Authentication")?503:500).json({error:message});
  }
});

app.post("/api/auth/login",async(req,res)=>{
  try{
    const email=String(req.body?.email||"").trim().toLowerCase();
    const password=String(req.body?.password||"");
    if(!/^\S+@\S+\.\S+$/.test(email)||!password)
      return res.status(400).json({error:"Enter a valid email and password"});
    await db();
    const user=await User.findOne({email}).select("+passwordHash +salt email plan").lean();
    if(!user)return res.status(401).json({error:"Invalid email or password"});
    const passwordHash=hash(password,user.salt);
    if(passwordHash!==user.passwordHash)return res.status(401).json({error:"Invalid email or password"});
    res.json({token:makeToken(user),user:{id:String(user._id),email:user.email,plan:user.plan}});
  }catch(error){
    const message=safeError(error,"Login failed");
    res.status(message.startsWith("Database")||message.startsWith("Authentication")?503:500).json({error:message});
  }
});

app.get("/api/auth/me",requireAuth,async(req,res)=>{
  try{
    await db();
    const user=await User.findById(req.auth.sub).select("email plan createdAt").lean();
    if(!user)return res.status(401).json({error:"User not found"});
    res.json({user:{id:String(user._id),email:user.email,plan:user.plan,createdAt:user.createdAt}});
  }catch(error){
    const message=safeError(error,"Session validation failed");
    res.status(message.startsWith("Database")?503:500).json({error:message});
  }
});

app.requireAuth=requireAuth;
module.exports=app;