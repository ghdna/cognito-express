import { CognitoExpressConfig, ValidateCallback } from './types';
export declare const DEFAULT_TOKEN_EXPIRATION = "3600000";
declare class CognitoExpress {
    userPoolId: string;
    tokenUse: string;
    tokenExpiration: string;
    iss: string;
    pems: Record<string, string>;
    constructor(config: CognitoExpressConfig);
    init(callback: (isOk: boolean) => void): Promise<void>;
    validate(token: string, callback: ValidateCallback): void;
    validate(token: string): Promise<Record<string, unknown>>;
}
export default CognitoExpress;
