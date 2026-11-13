import { createApp } from './app.js';

const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';

const app = createApp();

app.listen(PORT, HOST, () => {
  console.log(`What Your Browser Reveals server listening on http://${HOST}:${PORT}`);
  console.log(`Mode: Server-Side HTTP Document Header Inspection (TRUST_PROXY=${process.env.TRUST_PROXY || 'false'})`);
  console.log('Privacy: Request headers are processed strictly in memory and never logged or persisted.');
});
