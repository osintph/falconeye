# Contributing to FalconEye

Thanks for considering a contribution. This project exists to be useful to OSINT investigators, security researchers, and incident responders. Contributions that move it in that direction are welcome.

## Ways to contribute

### Report a bug

Open a GitHub issue with:

1. What you did (the steps, including the input you submitted)
2. What you expected to happen
3. What actually happened
4. Browser, OS, and rough time of day (helps correlate with server logs)

If the bug involves the live site at falconeye.osintph.info, include the rough time of the failed request so we can grep the server logs.

### Suggest a new tab or feature

Open a GitHub issue tagged "enhancement". Explain:

1. What problem are you trying to solve (real-world investigative scenario)
2. What data sources or techniques would the tab use
3. Why this fits in FalconEye specifically rather than a separate tool

The best tab suggestions come with concrete examples: "I work BEC cases and I keep needing to do X by hand, here's what an automated version would look like."

### Submit a pull request

For non-trivial changes, please open an issue first to discuss the approach. For small fixes (typos, broken links, dependency bumps), a direct PR is fine.

PR checklist:

- [ ] Code follows the existing style (FastAPI router per tab, vanilla JS, no new frontend frameworks)
- [ ] If you added a new dependency, add it to `requirements.txt` with a pinned major version
- [ ] If you added an API endpoint, add it to the README's API table
- [ ] If you added user-facing functionality, update the README's tab list and sitemap.xml
- [ ] If you added an LLM-powered feature, follow the safeguard pattern: hardcoded model, per-IP daily rate limit, env kill switch, prompt caching
- [ ] Tested locally with `uvicorn app.main:app --reload`
- [ ] No secrets, API keys, or operator hostnames committed

### Improve documentation

Documentation improvements are first-class contributions. Examples of useful doc PRs:

- Clearer install instructions for a specific Linux distro
- Self-hosting guide for non-OVH providers (AWS Lightsail, Hetzner, DigitalOcean, etc)
- Worked examples of using each tab for a specific investigation type
- Translating the privacy policy or contact form to another language

---

## Code style

- Python: PEP 8, type hints where they add clarity, no aggressive refactors of existing code unless the PR specifically calls that out
- JavaScript: ES2020+, no build step, no transpilation. Vanilla JS only.
- HTML: Tailwind utility classes only, no custom CSS files unless absolutely necessary (style.css exists for the few places it is)
- Commit messages: imperative mood, scoped prefix (`feat:`, `fix:`, `docs:`, `chore:`)

---

## What we will not merge

- Tabs that primarily exist to collect user data
- Tabs that require user accounts or login
- Features that require proprietary or paid third-party services without a viable free-tier fallback
- Closed-source dependencies
- Code that ships a backdoor, telemetry, ads, or tracking
- Anything that would change the AGPL-3.0 license

---

## License of your contributions

By submitting a pull request, you agree your contribution will be licensed under AGPL-3.0, the same license as the rest of the project.

---

## Code of conduct

Be useful. Be respectful. Disagree with ideas, not with people. If your PR is not merged, accept that and move on. If you feel a reviewer was unfair, contact the maintainer at security@osintph.info.
