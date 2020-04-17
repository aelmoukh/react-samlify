/**
 * Service Layer
 */
import * as jwt from 'jsonwebtoken';
import * as fs from "fs";

const SECRET = 'somethingverysecret';
// const RSA_PRIVATE_KEY = fs.readFileSync('./demos/private.key');

// this is a mock function, it should be used to interact with your database in real use case
export function getUser(login: string) {
  if (login === 'user.passify.io@gmail.com') {
    return {
      user_id: '21b06b08-f296-42f4-81aa-73fb5a8eac67',
      email: login
    };
  }
  return null;
}

export function createToken(payload) {
//   const jwtBearerToken = jwt.sign({}, RSA_PRIVATE_KEY, {
//     algorithm: 'RS256',
//     expiresIn: 120,
//     subject: payload
// }

  return jwt.sign(payload, SECRET);
}

export function verifyToken(token) {
  console.log("*********** verifications ********************");
  try {
    const payload = jwt.verify(token, SECRET);
    console.log("*********** valide ********************");
    return { verified: true, payload: payload };
  } catch(err) {
    console.log("*********** invalide ********************");
    return { verified: false, payload: null };
  }
}