import { VerifyErrors } from 'jsonwebtoken';
export declare type ValidateCallback = (err: VerifyErrors | Error | null, decoded?: object) => void;
export declare type JwtVerifyParams = {
    token: string;
    pem: string;
    iss: string;
    maxAge: string;
};
export declare type CognitoExpressConfig = {
    cognitoUserPoolId: string;
    tokenUse: string;
    /** Refer: maxAge from https://github.com/auth0/node-jsonwebtoken */
    tokenExpiration?: number | string;
    region: string;
};
