const _ = require('lodash');
const fetch = require('node-fetch');

module.exports = async function load(url) {
  const res = await fetch(url);
  return _.pick(await res.json(), ['id', 'name']);
};
