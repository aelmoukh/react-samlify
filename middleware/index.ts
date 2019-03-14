import * as samlify from 'samlify';
import * as fs from 'fs';
const binding = samlify.Constants.namespace.binding;

// configure okta idp
const oktaIdp = samlify.IdentityProvider({
  metadata: fs.readFileSync(__dirname + '/../metadata/okta.xml')
});

const oktaIdpEnc = samlify.IdentityProvider({
  metadata: fs.readFileSync(__dirname + '/../metadata/okta-enc.xml'),
  isAssertionEncrypted: true,
  messageSigningOrder: 'encrypt-then-sign'
});

// configure our service provider (your application)
const sp = samlify.ServiceProvider({
  entityID: 'http://localhost:8080/metadata',
  authnRequestsSigned: false,
  wantAssertionsSigned: true,
  wantMessageSigned: true,
  wantLogoutResponseSigned: true,
  wantLogoutRequestSigned: true,
  privateKey: fs.readFileSync(__dirname + '/../key/sign/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: false,
  assertionConsumerService: [{
    Binding: binding.post,
    Location: 'http://localhost:8080/sp/acs',
  }]
});

// encrypted response
const spEnc = samlify.ServiceProvider({
  entityID: 'http://localhost:8080/metadata?encrypted=true',
  authnRequestsSigned: false,
  wantAssertionsSigned: true,
  wantMessageSigned: true,
  wantLogoutResponseSigned: true,
  wantLogoutRequestSigned: true,
  privateKey: fs.readFileSync(__dirname + '/../key/sign/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  encPrivateKey: fs.readFileSync(__dirname + '/../key/encrypt/privkey.pem'),
  assertionConsumerService: [{
    Binding: binding.post,
    Location: 'http://localhost:8080/sp/acs?encrypted=true',
  }]
});

export const assignEntity = (req, res, next) => {

  req.idp = oktaIdp;
  req.sp = sp;

  if (req.query && req.query.encrypted) {
    req.idp = oktaIdpEnc;
    req.sp = spEnc; 
  }

  return next();

};