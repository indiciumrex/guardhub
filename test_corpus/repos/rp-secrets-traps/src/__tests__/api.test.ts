const key = '{{secret:stripe_live_secret:trap6}}';

test('rejects a revoked key', async () => {
  expect(await call(key)).toBe(401);
});
