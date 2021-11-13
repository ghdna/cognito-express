import chai from 'chai';
import Strategy from '../src';
import rewire from 'rewire';
import { CognitoExpressConfig } from '../src/types';

const expect = chai.expect;
const strategyConfig = {
  region: 'us-east-1',
  cognitoUserPoolId: 'us-east-1_PNBFQ9W7X',
  tokenUse: 'access', //Possible Values: access | id
  tokenExpiration: 3600000, //Up to default expiration of 1 hour (4000 ms)
};

//eslint-disable-next-line
const token =
  'eyJraWQiOiJVb0dmOG95UTNrbXB6WlZFWmZxS3RDQ0hIQ3lVNUo3RnV6dFRWSmxRNGtZPSIsImFsZyI6IlJTM' +
  'jU2In0.eyJzdWIiOiIzNzZkOWY5MC04MjkzLTRhODMtYjA0Yi0zYWRjZTJlYTkzZTAiLCJ0b2tlbl91c2UiOi' +
  'JhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiaXNzIjoiaHR0cHM6XC9' +
  'cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfZFhsRmVmNzN0IiwiZXhw' +
  'IjoxNTAzNDA5NjM5LCJpYXQiOjE1MDM0MDYwMzksImp0aSI6ImE1YjhjNWZhLWJiNDgtNGNkYi1hOTZiLTk4M' +
  'Tc3NjEyN2I1NyIsImNsaWVudF9pZCI6IjZ1ZDZ1cG9xaG5kYzd2Y3YxMDR2bG5hbHBuIiwidXNlcm5hbWUiOi' +
  'J2aXNhb2ZmaWNlcjFAY25hLmdvdiJ9.FL69JLtHFCeBU1nKYRyZYBBEO1TVaDCCuRTvrw_piSqLM_DQ2sUUJQ' +
  'Yr9Ww3DudaTcjHDkV_rJufb3BzAfVMG0pOkZit6JkTexoCOHzXRNn0Bgmk87vVB52H2zOe6hRw_pF90UUmg6q' +
  '9kYb2zapQg_-3ZvE1TiDQ0v45RZDKUHqWUFka3L3q6_uDHfCFrTr_APBN7y2u_w10jaL75CQ4h3RePOxKTiyS' +
  'jLq0FsFnl576eu_ZkoliUmApPCD618dRbu4kybCizbvYLLx8x-vM3CvPjnv_bXL1FtOWjzjSifuM5Hjnr1Fxo' +
  'zCBQipBZ7X6vQBKy5hNX17O3sBt9KXXlg';

chai.should();

describe('Strategy Negative Scenarios', () => {
  it('should not have config undefined', function () {
    expect(function () {
      new Strategy(undefined as unknown as CognitoExpressConfig);
    }).to.throw(
      TypeError,
      'Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express',
    );
  });

  it('should not have token use undefined', function () {
    expect(function () {
      new Strategy({
        region: 'us-east-1',
        cognitoUserPoolId: 'us-east-1_PNBFQ9W7X',
        tokenExpiration: 3600000, //Up to default expiration of 1 hour (4000 ms)
      } as CognitoExpressConfig);
    }).to.throw(TypeError, "Token use not specified in constructor. Possible values 'access' | 'id'");
  });

  it('should not have token be other than access or id', function () {
    expect(function () {
      new Strategy({
        region: 'us-east-1',
        tokenUse: 'hello', //Possible Values: access | id
        cognitoUserPoolId: 'us-east-1_PNBFQ9W7X',
        tokenExpiration: 3600000, //Up to default expiration of 1 hour (4000 ms)
      });
    }).to.throw(TypeError, "Token use values not accurate in the constructor. Possible values 'access' | 'id'");
  });

  it('should not have user pool undefined', function () {
    expect(function () {
      new Strategy({
        region: 'us-east-1',
        tokenUse: 'access', //Possible Values: access | id
        tokenExpiration: 3600000, //Up to default expiration of 1 hour (4000 ms)
      } as CognitoExpressConfig);
    }).to.throw(TypeError, 'Cognito User Pool ID is not specified in constructor');
  });

  it('should not have Region undefined', function () {
    expect(function () {
      new Strategy({
        cognitoUserPoolId: 'us-east-1_PNBFQ9W7X',
        tokenUse: 'access', //Possible Values: access | id
        tokenExpiration: 3600000, //Up to default expiration of 1 hour (4000 ms)
      } as CognitoExpressConfig);
    }).to.throw(TypeError, 'AWS Region not specified in constructor');
  });

  it('should fail to init', async function () {
    const strategy = new Strategy({ ...strategyConfig, cognitoUserPoolId: 'us-east-1_DEAD_POOL' });
    try {
      await strategy.init(() => undefined);
      expect(false).to.eql(true);
    } catch (e: any) {
      expect(e.message).to.match(/^Unable to generate certificate due to/);
    }
  });
});

describe('Strategy Positive Scenarios', () => {
  const app = rewire('../src/index.ts');
  let strategy: Strategy;

  it('should check if GeneratePem function exists', () => {
    strategy = new Strategy(strategyConfig);
    expect(strategy.init).to.be.a('function');
  });

  it('should check if jwtVerify function exists', () => {
    const jwtVerify = app.__get__('jwtVerify');
    expect(jwtVerify).to.be.a('function');
  });

  it('should check if configurationIsCorrect function exists', () => {
    const configurationIsCorrect = app.__get__('validateConfig');
    expect(configurationIsCorrect).to.be.a('function');
  });

  it('should check if Validate function exists', () => {
    strategy = new Strategy(strategyConfig);
    expect(strategy.validate).to.be.a('function');
  });

  it('should check if Strategy can initialized successfully', async () => {
    strategy = new Strategy(strategyConfig);
    await strategy.init((callback) => {
      expect(callback).to.eql(true);
    });
  });

  it('should check if Validate function can fail successfully when invalid token is passed', async () => {
    await strategy.init(() => {
      strategy.validate('token', function (err) {
        const msg = err && err.message;
        expect(msg).to.equal('Not a valid JWT token');
      });
    });
  });

  it('should check if Validate function can fail successfully when invalid token is passed (Promise)', async () => {
    await strategy.init(async () => {
      try {
        await strategy.validate('token');
        expect(true).to.eql(false);
      } catch (err) {
        expect(err).to.eql('Not a valid JWT token');
      }
    });
  });
});
