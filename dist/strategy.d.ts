import { CognitoIdToken, CognitoAccessToken } from "./Token";
export declare type CognitoExpressConfig = {
    cognitoUserPoolId: string;
    tokenUse: 'id' | 'access';
    region: string;
    tokenExpiration: number;
};
export default class CognitoExpress {
    private userPoolId;
    private tokenUse;
    private tokenExpiration;
    private iss;
    private promise;
    private pems;
    constructor(config: CognitoExpressConfig);
    private init;
    validate(token: string, callback?: (err: any, payload: CognitoIdToken | CognitoAccessToken) => void): Promise<CognitoIdToken | CognitoAccessToken>;
}
