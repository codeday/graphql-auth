const { MissingScopeError } = require('./errors');

/**
 * Takes a scope list from Auth0 and returns helper functions to check if the given token has a scope.
 *
 * @param {Array} scopes The list of scopes the application has.
 * @returns {object} Object with functions to validate scope permissions.
 */
module.exports.getScopeContextHelpers = (scopes) => {
  const hasScope = (scope) => (Array.isArray(scope) ? scope : [scope])
    .map((s) => scopes.includes(s))
    .reduce((accum, s) => accum || s, false);

  const requireScope = (scope) => {
    if (!hasScope(scope)) throw new MissingScopeError(scope);
  };

  return { hasScope, requireScope };
};

/**
 * Takes an event permission list from Auth0 and returns helper functions to check if the given token has a permission
 * for a given event.
 *
 * @param {Array} events K-V pair of eventId and permission.
 * @returns {object} Object with functions to validate permission for an event.
 */
module.exports.getEventContextHelpers = (events) => {
  const hasEvent = (event) => event in events;

  const requireEvent = (event) => {
    if (!hasEvent(event)) {
      throw new MissingScopeError(null, 'any');
    }
  };

  const hasEventScope = (event, permission) => {
    if (!hasEvent(event)) return false;
    const permissionArray = Array.isArray(permission) ? permission : [permission];
    return permissionArray.map((p) => events[event] === p).reduce((accum, p) => p || accum, false);
  };

  const requireEventScope = (event, permission) => {
    if (!hasEventScope(event, permission)) {
      throw new MissingScopeError(null, permission);
    }
  };

  return {
    hasEvent, requireEvent, hasEventScope, requireEventScope,
  };
};
