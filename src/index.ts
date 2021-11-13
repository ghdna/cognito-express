import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';
import { CognitoExpressConfig, JwtVerifyParams, ValidateCallback } from './types';
import fetch from 'node-fetch';

export const DEFAULT_TOKEN_EXPIRATION = `3600000`;

class CognitoExpress {
  userPoolId: string;
  tokenUse: string;
  tokenExpiration: string;
  iss: string;
  pems: Record<string, string> = {};

  constructor(config: CognitoExpressConfig) {
    if (!config)
      throw new TypeError(
        'Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express',
      );

    validateConfig(config);
    this.userPoolId = config.cognitoUserPoolId;
    this.tokenUse = config.tokenUse;
    this.tokenExpiration = `${config.tokenExpiration}` || DEFAULT_TOKEN_EXPIRATION;
    this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this.userPoolId}`;
  }

  async init(callback: (isOk: boolean) => void): Promise<void> {
    try {
      const responseObj = await fetch(`${this.iss}/.well-known/jwks.json`);
      const response = await responseObj.text();
      const keys = JSON.parse(response)['keys'];
      for (let i = 0; i < keys.length; i++) {
        const key_id = keys[i].kid;
        const modulus = keys[i].n;
        const exponent = keys[i].e;
        const key_type = keys[i].kty;
        const jwk = { kty: key_type, n: modulus, e: exponent };
        const pem = jwkToPem(jwk);
        this.pems[key_id] = pem;
      }
      callback(true);
    } catch (err) {
      callback(false);
      throw new TypeError('Unable to generate certificate due to \n' + err);
    }
  }

  validate(token: string, callback: ValidateCallback): void;
  validate(token: string): Promise<Record<string, unknown>>;
  validate(token: string, callback?: ValidateCallback): void | Promise<Record<string, unknown>> {
    const decodedJwt = jwt.decode(token, {
      complete: true,
    });

    if (!decodedJwt) return callbackElseThrow(new Error(`Not a valid JWT token`), callback);

    if (decodedJwt.payload.iss !== this.iss)
      return callbackElseThrow(new Error(`token is not from your User Pool`), callback);

    if (decodedJwt.payload.token_use !== this.tokenUse)
      return callbackElseThrow(new Error(`Not an ${this.tokenUse} token`), callback);

    const kid = decodedJwt.header.kid;
    const pem = this.pems && kid && this.pems[kid];

    if (!pem) return callbackElseThrow(new Error(`Invalid ${this.tokenUse} token`), callback);

    const params = {
      token: token,
      pem: pem,
      iss: this.iss,
      maxAge: this.tokenExpiration,
    };

    if (callback) {
      jwtVerify(params, callback);
    } else {
      return new Promise((resolve, reject) => {
        jwtVerify(params, (err, result) => {
          if (err) {
            reject(err);
          } else {
            resolve(result as Record<string, undefined>);
          }
        });
      });
    }
  }
}

function validateConfig(config: CognitoExpressConfig): boolean | never {
  let configurationPassed = false;
  switch (true) {
    case !config.region:
      throw new TypeError('AWS Region not specified in constructor');
    case !config.cognitoUserPoolId:
      throw new TypeError('Cognito User Pool ID is not specified in constructor');
    case !config.tokenUse:
      throw new TypeError("Token use not specified in constructor. Possible values 'access' | 'id'");
    case !(config.tokenUse == 'access' || config.tokenUse == 'id'):
      throw new TypeError("Token use values not accurate in the constructor. Possible values 'access' | 'id'");
    default:
      configurationPassed = true;
  }
  return configurationPassed;
}

function jwtVerify(params: JwtVerifyParams, callback: jwt.VerifyCallback): void {
  jwt.verify(
    params.token,
    params.pem,
    {
      issuer: params.iss,
      maxAge: params.maxAge,
    },
    function (err, payload) {
      if (err) return callback(err, undefined);
      return callback(null, payload);
    },
  );
}

function callbackElseThrow(err: Error, callback?: ValidateCallback) {
  if (callback) {
    callback(err);
  } else {
    throw err;
  }
}

export default CognitoExpress;
