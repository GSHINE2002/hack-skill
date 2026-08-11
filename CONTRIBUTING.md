# Contributing to Hack — Web Security Toolkit

First off, thanks for taking the time to contribute! 🎉

## 🚀 Ways to Contribute

- 🐛 **Report bugs** — Open an issue with reproduction steps
- 💡 **Suggest features** — New attack modules, wordlists, or automation
- 🔧 **Submit PRs** — Code improvements, new modules, documentation
- 📖 **Improve docs** — Fix typos, add examples, clarify instructions
- 🧪 **Add test cases** — Expand test coverage

## 📋 Development Setup

```bash
git clone https://github.com/GSHINE2002/hack-skill.git
cd hack-skill/scripts
pip install -r requirements.txt
playwright install chromium
```

## 🧭 Guidelines

### Code Style

- Python 3.11+
- Follow PEP 8 (with reasonable line length exceptions)
- Type hints encouraged but not mandatory
- Docstrings for public functions

### New Modules

When adding a new attack module:

1. Follow the existing module structure (When → Techniques → Code)
2. Add wordlist entries to `scripts/wordlists/` if applicable
3. Map the vulnerability to OWASP Top 10 in `wordlists/owasp_map.py`
4. Update `SKILL.md` with the new module documentation
5. Add a test case in `tests/`

### Commits

Use conventional commit format:

```
feat: add GraphQL batching attack
fix: CDP stealth patch for Chrome 120
docs: update Module 8 examples
refactor: simplify ZAP manager lifecycle
```

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code, test it works
3. Update documentation as needed
4. Ensure no secrets/credentials are committed
5. Open the PR with a clear title and description

## ⚠️ Security

- **Never** commit real credentials, API keys, or target URLs
- Use placeholder values (`target.com`, `evil.com`) in all examples
- Report security vulnerabilities in the toolkit itself via Issues (not public exploits)

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.
