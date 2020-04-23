import * as fs from "fs";
import * as bodyParser from "body-parser";
import { getUser, createToken, verifyToken } from "./services/auth";
import { assignEntity } from "./middleware";
import { Constants } from "samlify";
const cors = require('cors');
const url = require('url'); 
const session = require('express-session');
const home_url = 'http://localhost:4736/welcome';
export default function server(app) {
  app.use(bodyParser.urlencoded({ extended: false }));
  // for pretty print debugging
  app.set("json spaces", 2);
  // assign the session sp and idp based on the params
  app.use(assignEntity);
  app.use(cors());
  app.use(session({secret: 'sessionSecret', resave: false, saveUninitialized: false}));
  // assertion consumer service endpoint (post-binding)
  app.post("/sp/acs", async (req, res) => {
    try {
      const { extract } = await req.sp.parseLoginResponse(req.idp, "post", req);
      const { login } = extract.attributes;
      // get your system user
      const payload = getUser(login);

      // assign req user
      req.user = { nameId: login };

      if (payload) {
        // create session and redirect to the session page
        const token = createToken(payload);
        return res.redirect(url.format({pathname:req.session.redirectUrl,query: {"auth_token" :token}}));
      }
      throw new Error("ERR_USER_NOT_FOUND");
    } catch (e) {
      console.error("[FATAL] when parsing login response sent from okta", e);
      return res.redirect("/");
    }
  });

  // call to init a sso login with redirect binding
  app.get("/sso/redirect", async (req, res) => {
    
    const callerwebsite = req.protocol+"://"+(req.header('Referer') || req.originalUrl || req.url || '').split('/')[2] ;
    let callbackurl = decodeURI(req.query.callbackurl);
    
    if (req.session) {  
      req.session.redirectUrl = callerwebsite+callbackurl; 
      req.session.callerwebsite = callerwebsite; 
    }  
    const { id, context: redirectUrl } = await req.sp.createLoginRequest(
      req.idp,
      "redirect"
    );
    return res.redirect(redirectUrl);
  });

  app.get("/sso/post", async (req, res) => {
    const { id, context } = await req.sp.createLoginRequest(req.idp, "post");
    // construct form data
    const endpoint = req.idp.entityMeta.getSingleSignOnService(
      "post"
    ) as string;
    const requestForm = fs
      .readFileSync("./request.html")
      .toString()
      .replace("$ENDPOINT", endpoint)
      .replace("$CONTEXT", context);

    return res.send(requestForm);
  });

  // endpoint where consuming logout response
  app.post("/sp/sso/logout", async (req, res) => {
    const { extract } = await req.sp.parseLogoutResponse(req.idp, "post", req);
    console.log("**********logout consume******************");
    //console.log(req);
    //return res.redirect("/logout");
    console.log((req.header('Referer') || req.originalUrl || req.url || '').split('/')[2]);
    console.log(req.header('Referer'));
    console.log(req.originalUrl);
    console.log(req.url);
    console.log(req.origin);
    
    return res.redirect(home_url);
  });

  app.get("/sp/single_logout/redirect", async (req, res) => {
    const { context: redirectUrl } = await req.sp.createLogoutRequest(
      req.idp,
      "redirect",
      { logoutNameID: "user.passify.io@gmail.com" }
    );
    console.log("**********logout******************");
    console.log(redirectUrl);
    
    return res.redirect(redirectUrl);
  });

  // distribute the metadata
  app.get("/sp/metadata", (req, res) => {
    res.header("Content-Type", "text/xml").send(req.sp.getMetadata());
  });

  app.get("/idp/metadata", (req, res) => {
    res.header("Content-Type", "text/xml").send(req.idp.getMetadata());
  });

  // get user profile
  app.get("/profile", (req, res) => {
    try {
      const bearer = req.headers.authorization.replace("Bearer ", "");
      const { verified, payload } = verifyToken(bearer);
      if (verified) {
        return res.json({ profile: payload });
      }
      return res.send(401);
    } catch (e) {
      res.send(401);
    }
  });
}
