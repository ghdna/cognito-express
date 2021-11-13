import { VerifyErrors } from 'jsonwebtoken';

export type ValidateCallback = (err: VerifyErrors | Error | null, decoded?: object) => void;

export type JwtVerifyParams = {
  token: string;
  pem: string;
  iss: string;
  maxAge: string;
};

// export type DecodedJwt = {
//   payload: {
//     iss: string;
//     token_use: string;
//   };
//   header: { kid: string };
// };

export type CognitoExpressConfig = {
  cognitoUserPoolId: string;
  tokenUse: string;
  /** Refer: maxAge from https://github.com/auth0/node-jsonwebtoken */
  tokenExpiration?: number | string;
  region: string;
};
