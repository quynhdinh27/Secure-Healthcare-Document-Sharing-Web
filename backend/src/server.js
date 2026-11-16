const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

app.get('/health/live', (_request, response) => {
  response.status(200).json({ status: 'ok' });
});
app.get('/demo', (_request, response) => {
  response.type('html').send(`
    <!doctype html>
    <html lang="vi">
      <meta charset="utf-8">
      <title>Kiểm tra backend</title>
      <h1>Kiểm tra backend</h1>
      <button id="check">Kiểm tra</button>
      <pre id="result"></pre>

      <script>
        const result = document.getElementById('result');

        document.getElementById('check').onclick = async () => {
          result.textContent = 'Đang gọi API...';

          try {
            const response = await fetch('/health/live');
            const data = await response.text();
            result.textContent = 'HTTP ' + response.status + '\\n' + data;
          } catch {
            result.textContent = 'Không kết nối được với backend.';
          }
        };
      </script>
    </html>
  `);
});
app.listen(port, () => {
  console.log(`Backend running at http://localhost:${port}`);
});