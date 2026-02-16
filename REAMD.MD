# 🐟 Fishnet

**The only door between your AI agent and the real world.**

Local-first security proxy for AI agents. Single Rust binary. Open source. Nothing leaves your machine.

---

AI agents hold your API keys, make payments, execute trades, and talk to the internet on your behalf — with zero guardrails. Fishnet sits between your agent and the outside world, enforcing the rules you set.

Your agent never touches real credentials. Every request flows through Fishnet. Every decision is logged.

## What It Does

- **Credential Isolation** — Your API keys live in an encrypted vault. The agent gets a localhost proxy. It never sees the real keys.
- **Spend Caps & Rate Limits** — Set a daily budget. When it's hit, the door closes. No more $300 surprises from a runaway loop.
- **Endpoint Blocking** — Withdrawals from your exchange account? Blocked at the proxy layer. Physically impossible through Fishnet.
- **Onchain Permits** — Agent wants to swap on Uniswap? Fishnet checks the contract, the function, the amount — then signs a cryptographic permit. No permit, no execution.
- **Tamper-Proof Audit Trail** — Every approved and denied action is logged in a Merkle tree. Optionally generate ZK proofs that attest to compliance without revealing what your agent did.

## Who It's For

Anyone running an AI agent with access to paid APIs or real money. If your agent has an OpenAI key, a Binance key, or a funded wallet — you need this.

## Status

🚧 **Pre-release** — Actively building. Star the repo to follow along.

## Links

- 📖 Docs (coming soon)
- 🐦 [@FishnetDev](https://twitter.com/FishnetDev)
- 💬 Discord (coming soon)

---

*Built with Rust. Runs locally. Trusts no one.*