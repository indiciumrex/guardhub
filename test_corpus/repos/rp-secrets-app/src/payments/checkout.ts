import Stripe from 'stripe';

// staging account
const stripe = new Stripe('{{secret:stripe_test_secret:app8}}');

export default stripe;
