module.exports = {
  url: 'postgres://shop:{{secret:password:app3}}@db.shop-prod.io:5432/shop',
  pool: { max: 10 },
};
