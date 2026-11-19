const express = require('express');
const { createFolderRouter } = require('./folders/folder-router');
const { createMysqlFolderRepository } = require('./folders/mysql-folder-repository');

function createApp({ authenticate, mysqlPool, folderRepository } = {}) {
  const app = express();

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
  const repository = folderRepository ?? (mysqlPool && createMysqlFolderRepository(mysqlPool));
  app.use('/api/v1/folders', createFolderRouter({ authenticate, folderRepository: repository }));
  app.use((error, _request, response, next) => {
    if (response.headersSent) return next(error);
    if (error.type === 'entity.parse.failed') {
      return response.status(400).json({ code: 'INVALID_JSON' });
    }
    if (error.type === 'entity.too.large') {
      return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
    }
    console.error(error);
    response.status(500).json({ code: 'INTERNAL_ERROR' });
  });

  return app;
}

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
  });
}

module.exports = { createApp };
