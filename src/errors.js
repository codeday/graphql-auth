/* eslint-disable max-classes-per-file */

const makeRequirementMessage = Symbol('makeRequirementMessage');

module.exports.MissingScopeError = class extends Error {
  /**
   * Represents an error caused by the user not having a required scope.
   *
   * @param {Array|string} requiresGlobal The name of the global scope(s) required.
   * @param {Array|string} requiresEvent The name of the event scope(s) required.
   * @param {...*} args Other args to pass to the underlying exception.
   */
  constructor(requiresGlobal, requiresEvent, ...args) {
    super('', ...args);
    const requiresGlobalMessage = this[makeRequirementMessage](requiresGlobal);
    const requiresEventMessage = this[makeRequirementMessage](requiresEvent);
    const requiresMessage = [
      (requiresGlobalMessage ? `${requiresGlobalMessage} global scope` : null),
      (requiresEventMessage ? `${requiresEventMessage} event scope` : null),
    ].filter((e) => e).join(', or ');

    this.message = `You don't have permission for that.`;
    if (requiresMessage) this.message += `(Requires ${requiresMessage})`;
  }

  /**
   * Generates a string representing requirements.
   *
   * @param {Array|string} reqs The requirements.
   * @returns {string} The requirements string.
   */
  [makeRequirementMessage](reqs) {
    if (Array.isArray(reqs) && reqs.length > 1) {
      return `${reqs.slice(0, reqs.length - 1).join(', ')}, or ${reqs[reqs.length - 1]}`;
    }

    if (Array.isArray(reqs) && reqs.length > 0) {
      return reqs[0];
    }

    if (typeof reqs === 'string') {
      return reqs;
    }

    return null;
  }
};

module.exports.MustLogInError = class extends Error {
  /**
   * Represents an error caused by the user being unauthenticated.
   *
   * @param {...*} args Other args to pass to the underlying exception.
   */
  constructor(...args) {
    super(`You must be logged in.`, ...args);
  }
};
