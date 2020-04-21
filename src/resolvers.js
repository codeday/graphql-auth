module.exports.requireLoggedIn = () => (_, __, { auth }) => auth.requireLoggedIn();
module.exports.requireScope = (scope) => (_, __, { auth }) => auth.requireScope(scope);
