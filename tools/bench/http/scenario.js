import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    mixed: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 1000),
      timeUnit: '1s',
      duration: __ENV.DURATION || '30s',
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<20'],
    http_req_failed: ['rate<0.001'],
  },
};

const base = `http://127.0.0.1:${__ENV.PORT || 8081}`;
const echoBody = JSON.stringify({ message: 'Hello, World!' });

export default function () {
  const slot = Math.random();
  let response;
  if (slot < 0.7) {
    response = http.get(`${base}/json`);
    check(response, { 'json body': (r) => r.body === '{"message":"Hello, World!"}' });
  } else if (slot < 0.9) {
    response = http.get(`${base}/work?n=20`);
    check(response, { 'work body': (r) => r.status === 200 && r.json('n') === 20 && r.json('fib') === 6765 });
  } else {
    response = http.post(`${base}/echo`, echoBody, { headers: { 'Content-Type': 'application/json' } });
    check(response, { 'echo body': (r) => r.body === echoBody });
  }
}
