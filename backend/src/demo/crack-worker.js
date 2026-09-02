// One shard of the brute-force search over the Bangladeshi MSISDN space.
import crypto from 'node:crypto';
import { parentPort, workerData } from 'node:worker_threads';

const { target, prefix, from, to, deadline } = workerData;
const t = Buffer.from(target, 'hex');
let tried = 0;
let reported = 0;

for (let n = from; n < to; n++) {
  const candidate = prefix + String(n).padStart(8, '0');
  tried++;
  if (crypto.createHash('sha256').update(candidate, 'utf8').digest().equals(t)) {
    parentPort.postMessage({ found: true, number: candidate, tried: tried - reported });
    process.exit(0);
  }
  if ((tried & 0x3ffff) === 0) {
    parentPort.postMessage({ progress: true, tried: tried - reported });
    reported = tried;
    if (Date.now() > deadline) break;
  }
}
parentPort.postMessage({ found: false, tried: tried - reported });
