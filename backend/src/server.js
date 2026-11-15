const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

app.get('/health/live', (_request, response) => {
  response.status(200).json({ status: 'ok' });
});

app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});