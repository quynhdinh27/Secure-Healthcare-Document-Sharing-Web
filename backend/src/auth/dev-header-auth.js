// Development-only identity: trusts the X-Dev-User-Id header.
// config.js refuses AUTH_MODE=dev in production; replace with the Auth module's
// session middleware, which must set request.user = { id: '<decimal user id>' }.
const USER_ID = /^[1-9][0-9]{0,19}$/;

function devHeaderAuth(request, _response, next) {
  const id = request.get('x-dev-user-id');
  if (typeof id === 'string' && USER_ID.test(id)) request.user = { id };
  next();
}

module.exports = { devHeaderAuth };
