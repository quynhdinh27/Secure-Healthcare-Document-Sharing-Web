class AppError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}

function validationError(message = 'Invalid request input.') {
  return new AppError(400, 'VALIDATION_ERROR', message);
}

function unauthenticated(message = 'Authentication is required.') {
  return new AppError(401, 'UNAUTHENTICATED', message);
}

function invalidCredentials(message = 'Invalid email or password.') {
  return new AppError(401, 'INVALID_CREDENTIALS', message);
}

function forbidden(message = 'You do not have permission to perform this action.') {
  return new AppError(403, 'FORBIDDEN', message);
}

function csrfInvalid(message = 'Invalid or missing CSRF token.') {
  return new AppError(403, 'CSRF_INVALID', message);
}

function accountDisabled(message = 'Account is disabled.') {
  return new AppError(403, 'ACCOUNT_DISABLED', message);
}

function notFound(code, message) {
  return new AppError(404, code, message);
}

function conflict(code, message) {
  return new AppError(409, code, message);
}

module.exports = {
  AppError,
  validationError,
  unauthenticated,
  invalidCredentials,
  forbidden,
  csrfInvalid,
  accountDisabled,
  notFound,
  conflict,
};
