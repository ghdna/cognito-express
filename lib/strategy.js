"use strict";

const jwkToPem = require("jwk-to-pem"),
    request = require("request-promise"),
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
            this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this
                .userPoolId}`;
            this.promise = this.init(callback => {});
        }
    }

    init(callback) {
        return request(`${this.iss}/.well-known/jwks.json`)
            .then(response => {
                this.pems = {};
                let keys = JSON.parse(response)["keys"];
                for (let i = 0; i < keys.length; i++) {
                    let key_id = keys[i].kid;
                    let modulus = keys[i].n;
                    let exponent = keys[i].e;
                    let key_type = keys[i].kty;
                    let jwk = { kty: key_type, n: modulus, e: exponent };
                    let pem = jwkToPem(jwk);
                    this.pems[key_id] = pem;
                }
                callback(true);
            })
            .catch(function(err) {
                throw new TypeError(
                    "Unable to generate certificate due to \n" + err
                );
                callback(false);
            });
    }

    validate(token, callback) {
        // Perform all the validation work using promises and exceptions.
        const validatePromise = this.promise.then(() => {
            const decodedJwt = jwt.decode(token, { complete: true });

            if (!decodedJwt) throw `Not a valid JWT token`;

            if (decodedJwt.payload.iss !== this.iss)
                throw `token is not from your User Pool`;

            if (decodedJwt.payload.token_use !== this.tokenUse)
                throw `Not an ${this.tokenUse} token`;

            const kid = decodedJwt.header.kid;
            const pem = this.pems[kid];

            if (!pem) throw `Invalid ${this.tokenUse} token`;

            const params = {
                token: token,
                pem: pem,
                iss: this.iss,
                maxAge: this.tokenExpiration
            };

            return new Promise((resolve, reject) => {
                jwtVerify(params, (err, result) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                });
            });
        });

        // Adapt to the callback metaphor if necessary.
        if (callback) {
            validatePromise
                .then(value => callback(undefined, value))
                .catch(error => callback(error, undefined));
        } else {
            return validatePromise;
        }
    }
}

function configurationIsCorrect(config) {
    let configurationPassed = false;
    switch (true) {
        case !config.region:
            throw new TypeError("AWS Region not specified in constructor");
            break;
        case !config.cognitoUserPoolId:
            throw new TypeError(
                "Cognito User Pool ID is not specified in constructor"
            );
            break;
        case !config.tokenUse:
            throw new TypeError(
                "Token use not specified in constructor. Possible values 'access' | 'id'"
            );
            break;
        case !(config.tokenUse == "access" || config.tokenUse == "id"):
            throw new TypeError(
                "Token use values not accurate in the constructor. Possible values 'access' | 'id'"
            );
            break;
        default:
            configurationPassed = true;
    }
    return configurationPassed;
}

function jwtVerify(params, callback) {
    jwt.verify(
        params.token,
        params.pem,
        {
            issuer: params.iss,
            maxAge: params.maxAge
        },
        function(err, payload) {
            if (err) return callback(err, null);
            return callback(null, payload);
        }
    );
}

module.exports = CognitoExpress;
