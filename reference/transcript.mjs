import {createHash} from 'node:crypto';
// The caller must validate the JWS and its payload contract independently.
export function timestampImprint(compactJWS) {
  if(typeof compactJWS!=='string'||!/^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+$/.test(compactJWS))
    throw new Error('EXACT_COMPACT_JWS_REQUIRED');
  return createHash('sha256').update(Buffer.from(compactJWS,'ascii')).digest();
}
