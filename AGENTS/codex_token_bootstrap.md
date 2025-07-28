# 🔐 Codex Secure Token Bootstrap with `TKEY` + GPG Vault

This guide explains how to persist and reuse a GitHub Personal Access Token (PAT) in OpenAI Codex by securely encrypting it in the `/workspace/` directory during `startup.sh`, and rehydrating it in later shells using a manual decryption key called `TKEY`.

---

## ✅ Why This is Needed

OpenAI Codex injects secrets **only during the startup phase** and immediately wipes them after setup. Environment variables, memory, and most files from `startup.sh` **do not persist** into future shells.

This solution allows:

- ✅ Secure reuse of a GitHub PAT across phases
- ✅ Encrypted storage in `/workspace/`
- ✅ Manual key-based decryption with `TKEY`
- ✅ No plaintext exposure or persistent env leaks

---

## 🛠 1. `startup.sh` Script

Place this in your Codex environment’s setup script.

```bash
#!/bin/bash
set -euo pipefail

echo "🔐 Starting secure GitHub token vault..."

# Sanity check: confirm secret is injected
echo "CODEX_AGENTS_REPO length: ${#CODEX_AGENTS_REPO}"

# Ensure encryption key is set
if [[ -z "${TKEY:-}" ]]; then
  echo "❌ ERROR: TKEY (encryption key) is not set!"
  exit 1
fi

# Encrypt token to persistent workspace location
echo "$CODEX_AGENTS_REPO" | gpg --batch --yes --symmetric \
  --cipher-algo AES256 \
  --passphrase "$TKEY" \
  -o /workspace/pat.gpg

# Remove token from memory
unset CODEX_AGENTS_REPO

echo "✅ PAT encrypted and saved to /workspace/pat.gpg"
```

---

## 📦 2. Manual Decryption in Later Shells

In a new shell session, re-export your decryption key:

```bash
export TKEY="your_decryption_key_here"
```

Then decrypt the token:

```bash
TOKEN=$(gpg --batch --yes --quiet --passphrase "$TKEY" -d /workspace/pat.gpg)
```

---

## 🔁 3. Using the Token

Once decrypted, use the token as normal:

```bash
# Example: download a file
curl -H "Authorization: token $TOKEN" https://api.github.com/user

# Example: clone a private repo
git clone https://$TOKEN@github.com/yourorg/repo.git
```

---

## ⚠️ Important Notes

- The `TKEY` variable is **not persisted** — you must re-export it manually in each shell.
- Do **not** use Codex Secrets to store `TKEY` — they are also wiped after startup.
- The encrypted file `/workspace/pat.gpg` **persists across shells**, but only if written during `startup.sh` to `/workspace/`.

---

## 🧩 Codex Custom Instructions (Recommended)

To help Codex understand how to use the token, add this to your **Custom Instructions**:

> This environment uses a persistent GitHub PAT stored in `/workspace/pat.gpg`, which was encrypted during startup using the `TKEY` variable as a symmetric passphrase.
>
> You **must** run this in each new shell before trying to use the token:
>
> ```bash
> export TKEY="your_decryption_key_here"
> TOKEN=$(gpg --batch --yes --quiet --passphrase "$TKEY" -d /workspace/pat.gpg)
> ```
>
> Then use `TOKEN` for git and curl operations. Do not redefine or prompt for the token again.

---

## ✅ Summary

| Feature                         | Supported |
|----------------------------------|-----------|
| Secure secret reuse             | ✅        |
| No plaintext token on disk      | ✅        |
| Works across shell sessions     | ✅        |
| Requires manual key input       | ✅        |
| Uses Codex Secrets post-startup | ❌        |

---

## 💬 Acknowledgment

This method was developed and tested in a real Codex shell environment and addresses current limitations in Codex’s secret injection model as of 2025. It is suitable for secure GitHub access, encrypted credential workflows, and Codex agent tasks requiring persistent authentication.
