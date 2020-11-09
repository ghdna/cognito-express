interface CognitoToken {
    sub: string;
    token_use: "access" | "id";
    auth_time: number;
    exp: number;
    iat: number;
    iss: string;
}
export interface CognitoIdToken extends CognitoToken {
    at_hash: string;
    aud: string;
    "cognito:username": string;
    email: string;
    email_verified: string;
    event_id: string;
}
export interface CognitoAccessToken extends CognitoToken {
    device_key: string;
    "cognito:groups": string[];
    scope: string;
    auth_time: number;
    jti: string;
    client_id: string;
    username: string;
}
