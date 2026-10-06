import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,verify,createHash} from 'node:crypto';
import {timestampImprint} from './transcript.mjs';
test('the timestamp covers the original signed serialization and excludes later augmentation',()=>{
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const part=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
  const input=part({alg:'ES256',typ:'example-evidence+jwt'})+'.'+part({event:'synthetic',document:'sha256:example'});
  const signature=sign('sha256',Buffer.from(input),{key:privateKey,dsaEncoding:'ieee-p1363'});
  assert(verify('sha256',Buffer.from(input),{key:publicKey,dsaEncoding:'ieee-p1363'},signature));
  const core=input+'.'+signature.toString('base64url'), before=timestampImprint(core);
  const packageValue={evidence:core,timestamps:[]};
  packageValue.timestamps.push('synthetic-token-placeholder');
  assert.deepEqual(timestampImprint(packageValue.evidence),before);
  assert.deepEqual(before,createHash('sha256').update(Buffer.from(core,'ascii')).digest());
  assert.notDeepEqual(timestampImprint(core.slice(0,-1)+(core.endsWith('A')?'B':'A')),before);
  assert.notDeepEqual(timestampImprint(part({alg:'ES256'})+'.'+part({event:'changed'})+'.'+signature.toString('base64url')),before);
  assert.throws(()=>timestampImprint(core+'\n'),/EXACT_COMPACT_JWS_REQUIRED/);
});
