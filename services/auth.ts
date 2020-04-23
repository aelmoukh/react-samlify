/**
 * Service Layer
 */
import * as jwt from "jsonwebtoken";
import * as fs from "fs";

const RSA_PRIVATE_KEY = fs.readFileSync("key/sign/private.key");
const RSA_PUBLIC_KEY = fs.readFileSync("key/sign/public.key");

// this is a mock function, it should be used to interact with your database in real use case
export function getUser(login: string) {
  if (login === "user.passify.io@gmail.com") {
    return {
      user_id: "21b06b08-f296-42f4-81aa-73fb5a8eac67",
      name: "ayoub_from_backend",
      email: login
    };
  }
  return null;
}

export function createToken(payload) {
  var signOptions = {
    issuer: "app automation",
    subject: "par_apps.mail",
    audience: "http://appsautomation.safe.socgen",
    expiresIn: "1h",
    algorithm: "RS512" // RSASSA [ "RS256", "RS384", "RS512" ]
  };
  return jwt.sign(payload, RSA_PRIVATE_KEY, signOptions);
}

export function verifyToken(token) {
  var verifyOptions = {
    issuer: "app automation",
    subject: "par_apps.mail",
    audience: "http://appsautomation.safe.socgen",
    expiresIn: "1h",
    algorithm: ["RS512"]
   };
  try {
    const payload = jwt.verify(token, RSA_PUBLIC_KEY,verifyOptions);
    return { verified: true, payload: payload };
  } catch (err) {
    return { verified: false, payload: null };
  }
}
