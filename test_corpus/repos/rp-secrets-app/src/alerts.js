const WEBHOOK = '{{secret:slack_webhook:app6}}';

export async function alert(text) {
  await fetch(WEBHOOK, { method: 'POST', body: JSON.stringify({ text }) });
}
