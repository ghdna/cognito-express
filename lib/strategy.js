"use strict";

const jwkToPem = require("jwk-to-pem"),
    needle = require("needle"),
    jwt = require("jsonwebtoken");

class CognitoExpress {
    constructor(config) {
        if (!config) {
            throw new TypeError(
                "Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express"
            );
        }

        if (!config.region)
            throw new TypeError("AWS Region not specified in constructor");

        if (!config.cognitoUserPoolId)
            throw new TypeError(
                "Cognito User Pool ID is not specified in constructor"
            );

        if (!config.tokenUse)
            throw new TypeError(
                "Token use not specified in constructor. Possible values 'access' | 'id'"
            );

        if (!(config.tokenUse == "access" || config.tokenUse == "id"))
            throw new TypeError(
                "Token use values not accurate in the constructor. Possible values 'access' | 'id'"
            );

        this.userPoolId = config.cognitoUserPoolId;
        this.tokenUse = config.tokenUse;
        this.tokenExpiration = config.tokenExpiration || 3600000;
        this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this
            .userPoolId}`;

        this.init(callback => {});
    }

    init(callback) {
        needle.get(`${this.iss}/.well-known/jwks.json`, (error, response) => {
            if (!error && response.statusCode == 200) {
                this.pems = {};
                let keys = response.body["keys"];

                //Convert each key to PEM
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
            } else {
                throw new TypeError("Unable to generate certificate");
                callback(false);
            }
        });
    }

    validate(token, callback) {
        let decodedJwt = jwt.decode(token, { complete: true });

        if (!decodedJwt) {
            return callback(`Not a valid JWT token`, null);
        }

        if (decodedJwt.payload.iss !== this.iss) {
            return callback(`token is not from your User Pool`, null);
        }

        if (decodedJwt.payload.token_use !== this.tokenUse) {
            return callback(`Not an ${this.tokenUse} token`, null);
        }

        let kid = decodedJwt.header.kid;
        let pem = this.pems[kid];

        if (!pem) {
            return callback(`Invalid ${this.tokenUse} token`, null);
        }

        jwt.verify(
            token,
            pem,
            {
                issuer: this.iss,
                maxAge: this.tokenExpiration
            },
            function(err, payload) {
                if (err) return callback(err, null);
                return callback(null, payload);
            }
        );
    }
}

module.exports = CognitoExpress;
