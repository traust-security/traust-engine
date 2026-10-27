import axios from "axios";

export async function proxy(req: any, res: any): Promise<void> {
  const target = req.query.endpoint;
  // ruleid: traust-ts-ssrf-request-taint
  await fetch(target);

  // ruleid: traust-ts-ssrf-request-taint
  await axios.get(`https://${req.params.cluster}/api/v1/status`);

  // ok: traust-ts-ssrf-request-taint
  await fetch("https://api.openshift.com/healthz");

  // ruleid: traust-ts-ssrf-request-taint
  await got.get(req.body.webhookUrl);

  // ruleid: traust-ts-ssrf-request-taint
  https.request(req.query.callback, () => undefined);

  // ruleid: traust-ts-ssrf-request-taint
  await axios.request({ url: req.body.target });
}
