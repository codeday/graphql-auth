const JwksClient = require('jwks-rsa');
const JwtLruCache = require('jsonwebtoken-lru-cache');

/**
 * Takes a scope list from Auth0 and returns helper functions to check if the given token has a scope.
 *
 * @param {Array} scopes The list of scopes the application has.
 * @returns {object} Object with functions to validate scope permissions.
 */
const getScopeContextHelpers = (scopes) => ({
  hasScope: (scope) => (Array.isArray(scope) ? scope : [scope])
    .map((s) => scopes.includes(s))
    .reduce((accum, s) => accum || s, false),
  requireScope: (scope) => { if (!this.hasScope(scope)) throw new Error(`The "${scope}" scope is required.`); },
});

/**
 * Takes an event permission list from Auth0 and returns helper functions to check if the given token has a permission
 * for a given event.
 *
 * @param {Array} events K-V pair of eventId and permission.
 * @returns {object} Object with functions to validate permission for an event.
 */
const getEventContextHelpers = (events) => ({
  hasEvent: (event) => event in events,
  requireEvent: (event) => {
    if (!this.hasEvent(event)) {
      throw new Error(`You do not have permissions for that event.`);
    }
  },
  hasEventScope: (event, permission) => {
    if (!this.hasEvent(event)) return false;
    const permissionArray = Array.isArray(permission) ? permission : [permission];
    return permissionArray.map((p) => events[event] === p).reduce((accum, p) => p || accum, false);
  },
  requireEventScope: (event, permission) => {
    if (!this.hasEventScope(event, permission)) {
      throw new Error(`You do not have the necessary permissions for that event.`);
    }
  },
});

/**
 * Builds a function which provides user and auth context given an auth0 bearer token.
 *
 * @param {string} audience The application audience string to validate.
 * @param {string} issuer The auth0 issuer (a URL).
 * @returns {Function} A function which takes a request, and sets the appropriate context.
 */
module.exports = (audience, issuer) => {
  // Set up JWKS to fetch the RSA signing key from our Auth0 issuer.
  const jwks = JwksClient({
    jwksUri: `${issuer}/.well-known/jwks.json`,
    jwksRequestsPerMinute: 5,
    rateLimit: true,
    cache: true,
  });

  // Set up a cache so we don't have to revalidate tokens with every request.
  const tokenCache = new JwtLruCache(
    1024 * 1024 * 10,
    (header, callback) => jwks.getSigningKey(header.kid, (_, key) => callback(null, key.publicKey || key.rsaPublicKey)),
    {
      audience,
      issuer,
      algorithms: ['RS256'],
    }
  );

  // Return a function which takes res, and returns the context to attach to the request.
  return async ({ header: { authorization } }) => {
    let user = {};
    const auth = {
      isLoggedIn: false,
      scopes: [],
      events: [],
    };

    const [authType, token] = (authorization || '').split(/\s+/, 2);
    if (authType.toLowerCase() === 'bearer' && token) {
      const {
        sub: userId,
        email,
        scope,
        'https://codeday.xyz/username': username,
        'https://codeday.xyz/email': corporateEmail,
        'https://codeday.xyz/phone_number': phoneNumber,
        'https://codeday.xyz/pronoun': pronoun,
        'https://codeday.xyz/events': events,
      } = await tokenCache.verifyAsync(token);
      auth.isLoggedIn = true;
      auth.scopes = scope.split(/\s+/g);
      auth.events = events;
      user = {
        userId,
        username,
        email,
        corporateEmail,
        phoneNumber,
        pronoun,
      };
    }
    const scopeHelpers = getScopeContextHelpers(auth.scopes);
    const eventScopeHelpers = getEventContextHelpers(auth.events);
    return {
      auth: {
        ...auth,
        ...scopeHelpers,
        ...eventScopeHelpers,
        requireLoggedIn: () => { if (!auth.isLoggedIn) throw new Error('You must be logged in.'); },
        hasScopeOrEvent: (scope, event) => (
          scopeHelpers.hasScope(scope) || eventScopeHelpers.hasEvent(event)
        ),
        requireScopeOrEvent: (scope, event) => {
          if (!this.hasScopeOrEvent(scope, event)) {
            throw new Error(`You don't have permission for that.`);
          }
        },
        hasScopeOrEventScope: (scope, event, eventScope) => (
          scopeHelpers.hasScope(scope) || eventScopeHelpers.hasEventScope(event, eventScope)
        ),
        requireScopeOrEventScope: (scope, event, eventScope) => {
          if (!this.hasScopeOrEventScope(scope, event, eventScope)) {
            throw new Error(`You don't have permission for that.`);
          }
        },
      },
      user,
    };
  };
};
