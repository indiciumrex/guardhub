const cfg = { api: "/api", token: "{{secret:github_pat:ks-github}}" };
fetch(cfg.api, { headers: { Authorization: "token " + cfg.token } });
