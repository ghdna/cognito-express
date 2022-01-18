"use strict";

const jwkToPem = require("jwk-to-pem"),
  axios = require("axios"),
  jwt = require("jsonwebtoken");

class CognitoExpress {
  constructor(config) {
    if (!config)
      throw new TypeError(
        "Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express"
      );

    if (configurationIsCorrect(config)) {
      this.userPoolId = config.cognitoUserPoolId;
      this.tokenUse = config.tokenUse;
      this.tokenExpiration = config.tokenExpiration || 3600000;
      this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this.userPoolId}`;
      this.hasFinishedProcessing = this.init();
      this.pems = {};
    }
  }

  init() {
    return new Promise(async (resolve, reject) => {
      try {
        const response = await axios(`${this.iss}/.well-known/jwks.json`);
        if (response.data.keys) {
          const keys = response.data.keys;
          for (let i = 0; i < keys.length; i++) {
            let key_id = keys[i].kid;

            let modulus = keys[i].n;
            let exponent = keys[i].e;
            let key_type = keys[i].kty;
            let jwk = {
              kty: key_type,
              n: modulus,
              e: exponent,
            };
            let pem = jwkToPem(jwk);
            this.pems[key_id] = pem;
          }
          resolve();
        }
      } catch (err) {
        console.error(err);
        reject("Unable to generate certificate due to \n" + err);
      }
    });
  }

  async validate(token, callback) {
    await this.hasFinishedProcessing;
    return new Promise(async (resolve, reject) => {
      let decodedJwt = jwt.decode(token, {
        complete: true,
      });
      try {
        if (!decodedJwt) throw new TypeError("Not a valid JWT token");

        if (decodedJwt.payload.iss !== this.iss)
          throw new TypeError("token is not from your User Pool");

        if (decodedJwt.payload.token_use !== this.tokenUse)
          throw new TypeError(`Not an ${this.tokenUse} token`);

        let kid = decodedJwt.header.kid;
        let pem = this.pems[kid];

        if (!pem) throw new TypeError(`Invalid ${this.tokenUse} token`);

        const result = jwt.verify(token, pem, {
          issuer: this.iss,
          maxAge: this.tokenExpiration,
        });
        if (callback) {
          callback(null, result);
        } else {
          resolve(result);
        }
      } catch (error) {
        console.error(error);
        if (callback) {
          callback(error, null);
        } else {
          reject(error);
        }
      }
    });
  }
}

function configurationIsCorrect(config) {
  let configurationPassed = false;
  switch (true) {
    case !config.region:
      throw new TypeError("AWS Region not specified in constructor");

    case !config.cognitoUserPoolId:
      throw new TypeError(
        "Cognito User Pool ID is not specified in constructor"
      );

    case !config.tokenUse:
      throw new TypeError(
        "Token use not specified in constructor. Possible values 'access' | 'id'"
      );

    case !(config.tokenUse == "access" || config.tokenUse == "id"):
      throw new TypeError(
        "Token use values not accurate in the constructor. Possible values 'access' | 'id'"
      );

    default:
      configurationPassed = true;
  }
  return configurationPassed;
}

module.exports = CognitoExpress;
