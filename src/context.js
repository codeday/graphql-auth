const JwksClient = require('jwks-rsa');
const JwtLruCache = require('jsonwebtoken-lru-cache');
const { MissingScopeError, MustLogInError } = require('./errors');
const { getScopeContextHelpers, getEventContextHelpers } = require('./context-helpers');

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
  return async ({ req: { headers: { authorization } } }) => {
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

    /**
     * @param scope
     * @param event
     */
    const hasScopeOrEvent = (scope, event) => (
      scopeHelpers.hasScope(scope) || eventScopeHelpers.hasEvent(event)
    );

    /**
     * @param scope
     * @param event
     */
    const requireScopeOrEvent = (scope, event) => {
      if (!hasScopeOrEvent(scope, event)) {
        throw new MissingScopeError(scope, 'any');
      }
    };

    /**
     * @param {string|Array} scope The global scopes to check.
     * @param {string} event The event ID to check.
     * @param {string|Array} eventScope The event scope(s) to check.
     * @returns {boolean} True if the
     */
    const hasScopeOrEventScope = (scope, event, eventScope) => (
      scopeHelpers.hasScope(scope) || eventScopeHelpers.hasEventScope(event, eventScope)
    );

    /**
     * @param scope
     * @param event
     * @param eventScope
     */
    const requireScopeOrEventScope = (scope, event, eventScope) => {
      if (!hasScopeOrEventScope(scope, event, eventScope)) {
        throw new MissingScopeError(scope, eventScope);
      }
    };

    return {
      auth: {
        ...auth,
        ...scopeHelpers,
        ...eventScopeHelpers,
        hasScopeOrEvent,
        requireScopeOrEvent,
        hasScopeOrEventScope,
        requireScopeOrEventScope,
        requireLoggedIn: () => { if (!auth.isLoggedIn) throw new MustLogInError(); },
      },
      user,
    };
  };
};
