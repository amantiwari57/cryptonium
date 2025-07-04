module.exports = {
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  extends: [
    'eslint:recommended',
  ],
  rules: {
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
  env: {
    node: true,
    es6: true,
    jest: true,
  },
  ignorePatterns: [
    'lib/',
    'node_modules/',
    '*.js',
    '*.d.ts'
  ],
}; 