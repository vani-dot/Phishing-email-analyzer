# Setup Guide — Phishing Email Analyzer

Everything you need to get this running, from a fresh machine to a working
analyser. No prior knowledge of the project assumed.

---

## 1. What this is

You give it an email. It tells you whether that email is **phishing**, **spam**,
**suspicious**, or **genuine** — and explains why, in writing.

It works in two ways at once:

- A **rules engine** checks things that can be computed exactly: whether the
  sender's DKIM signature is aligned, whether a link goes where it claims,
  whether an attachment is really the file type it says it is.
- An **AI agent** investigates. It is given tools and has to go and look —
  read the headers, decompose the links, search the body — then reach a
  conclusion and argue against itself before committing.

**It works without the AI.** With no API key it runs rules-only: slower to
catch subtle attacks, but fully functional, completely offline, and its
results never change between runs.

---

## 2. What you need

| | |
|---|---|
| Python | 3.9 or newer (`python3 --version` to check) |
| Disk | about 150 MB |
| Internet | only for installation, and for the AI layer if you enable it |
| Operating system | macOS, Linux or Windows |

You do **not** need a database server, Docker, or Node.js.

---

## 3. Installation

Unzip the project somewhere, open a terminal, and go into the folder:

```bash
cd "Phishing Email Analyzer"
```

### Create a virtual environment

This keeps the project's packages separate from the rest of your system.

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

You will know it worked because your prompt now starts with `(.venv)`.

### Install the packages

```bash
pip install -r requirements.txt
```

Ten packages, about 30 seconds. If `argon2-cffi` fails to build on Windows,
install the Visual C++ Build Tools, or skip it — the project falls back to a
different password hashing method automatically.

### Check everything works (optional)

The checks need two packages the app itself does not:

```bash
pip install -r requirements-dev.txt
```

Then:

```bash
./selfcheck.sh          # macOS / Linux
```

You should see **"All 75 checks passed."** It becomes 77 once an AI key is
configured — the two extra checks test the providers.

On Windows, run the test suite instead:

```powershell
python -m pytest tests/ -q
```

You should see **268 passed**.

Skip this entirely if you just want to use the app. It is a verification
step, not part of the install.

---

## 4. Start it

```bash
python app.py
```

You will see something like this:

```
========================================================================
  Phishing Email Analyzer
========================================================================

  FIRST RUN — an administrator account has been created.

      username:  Vani
      password:  Vani

  Mode      : RULES-ONLY (no API key configured)
  URL       : http://127.0.0.1:8000
========================================================================
```

Open **http://127.0.0.1:8000** in your browser and sign in with
**`Vani` / `Vani`**.

To stop it, press `Ctrl+C` in the terminal.

### About that password

`Vani` / `Vani` is a deliberately simple default so the project is usable
immediately. It is stored properly hashed, not in plain text — but it *is*
published in this document, so treat it accordingly:

- Keep the server on `127.0.0.1` (the default). That means only your own
  computer can reach it.
- **Do not** put it on a network, forward the port, or tunnel it while that
  password is in place.
- If you ever do want it reachable by others, change the password first:
  **Users → Vani → Reset password**.

---

## 5. Using it

### The four sections

**Dashboard** — how many emails you have analysed, how they broke down, a
14-day activity chart, and which detection rules fire most often. Every number
is calculated live from the database.

**Analyzer** — where the work happens. Two ways to give it an email:

  1. **Paste** the full email source into the box.
  2. **Upload** a file: `.eml`, `.txt`, `.md`, `.msg` or `.mbox`, up to 2 MB.

  There are also **sample buttons** — seven prepared emails you can analyse
  with one click. Start there.

**History** — every analysis is saved. Search by subject or sender, filter by
verdict, sort by risk. Click any row to reopen the full report. The **JSON**
button downloads it.

**Users** — create accounts for other people with specific permissions.
**Audit** — every login, failure and permission denial, with the source IP.

### How to get the full source of a real email

The analyser needs the **headers**, not just the visible text. Headers are
where most of the evidence lives.

| Mail client | How |
|---|---|
| Gmail | Open the email → ⋮ menu (top right) → **Show original** → copy all |
| Outlook | Open the email → **File** → **Properties** → copy the Internet headers box |
| Apple Mail | Open the email → **View** → **Message** → **Raw Source** |
| Thunderbird | Open the email → **Ctrl+U** (View Source) |
| Yahoo | Open the email → **More** → **View raw message** |

Paste the whole thing into the Analyzer box.

You can paste just the body text if that is all you have — the report will say
plainly that header checks could not run, and lower its confidence accordingly.

### Reading a report

- **Risk gauge** — 0 to 100.
- **Verdict badge** — PHISHING / SUSPICIOUS / SPAM / GENUINE.
- **Theft vector badges** — *why* it is phishing: `credential request`,
  `brand impersonation`, `payment redirection`, `harvesting attachment`. A
  message cannot be labelled PHISHING without at least one.
- **`sender verified`** — the sender's DKIM signature is aligned and DMARC
  passed. Cryptographic proof the domain authorised the message.
- **Evidence cards** — click to expand. Each shows what was found, why it
  matters, and how many points it contributed.
- **Investigation trail** — which tools the AI called, in order. This is the
  audit trail of how it reached its conclusion.

### Score bands

| Score | Verdict | Meaning |
|---|---|---|
| 75–100 | PHISHING | Theft vector present and deception is clear |
| 50–74 | SUSPICIOUS | Something is wrong but no theft vector is provable |
| 25–49 | SPAM | Unsolicited commercial mail. Unwanted, not dangerous |
| 0–24 | GENUINE | No adverse evidence, or positive proof of legitimacy |

---

## 6. Turning on the AI layer (optional)

The analyser is fully functional without this. Adding a key makes it
noticeably better at subtle attacks — particularly business email compromise,
where a real, correctly-authenticated mailbox makes an illegitimate request
and there is no technical artefact to catch.

### Get a free key

**Groq** (recommended — fast, generous free tier):
1. Go to https://console.groq.com
2. Sign up
3. **API Keys** → **Create API Key**
4. Copy it (starts with `gsk_`)

### Configure it

Copy the template:

```bash
cp .env.example .env          # macOS / Linux
copy .env.example .env        # Windows
```

Open `.env` in any text editor and fill in:

```ini
PEA_LLM_PROVIDER=groq
PEA_LLM_API_KEY=gsk_your_key_here
PEA_LLM_BASE_URL=https://api.groq.com/openai/v1
PEA_LLM_MODEL=openai/gpt-oss-120b
```

Restart the app. The banner should now say `rules + AI`.

Check it is working:

```bash
python main.py --probe
```

```
  role      provider  model                     status      latency
  -----------------------------------------------------------------
  primary   groq      openai/gpt-oss-120b       up            333ms
```

### A second provider (optional but recommended)

Free tiers run out. If you configure a fallback, the analyser switches to it
automatically when the first one rate-limits or fails, instead of silently
dropping back to rules-only:

```ini
PEA_LLM_FALLBACK_PROVIDER=apmix
PEA_LLM_FALLBACK_API_KEY=apx_live_your_key_here
PEA_LLM_FALLBACK_BASE_URL=https://api.apmix.ai/v1
PEA_LLM_FALLBACK_MODEL=gpt-5.6-luna-free
```

Any provider speaking the OpenAI API format works — Groq, apmix, OpenRouter,
Together, or a local Ollama install. There is no vendor SDK, so switching is
purely configuration.

### Keep your key private

`.env` is listed in `.gitignore` and is never committed. Do not paste your key
into chat, screenshots, or a shared document. If you think it has leaked,
delete it in the provider's console and create a new one.

---

## 7. Using it from the command line

```bash
python main.py suspicious.eml              # analyse one file
python main.py suspicious.eml -v           # show the reasoning for every finding
python main.py suspicious.eml --json       # machine-readable output
python main.py --all samples/              # summary table for a folder
python main.py --probe                     # check the AI providers
cat message.txt | python main.py -         # read from standard input
```

Exit codes, for scripting: `0` genuine, `2` spam, `3` suspicious,
`4` phishing, `1` error.

---

## 8. Measuring how well it works

Two harnesses are included.

**Regression** — ten emails covering specific failure cases, with five
acceptance criteria:

```bash
python regression.py
python regression.py --llm      # with the AI layer
```

**Evaluation** — precision, recall, F1 and a confusion matrix against any
labelled corpus:

```bash
python evaluate.py corpus/eval50 --no-llm
python evaluate.py corpus/eval50 --csv results.csv
```

A corpus is just three folders:

```
corpus/
  phishing/   *.eml
  spam/       *.eml
  genuine/    *.eml
```

`corpus/eval50/` contains 50 prepared emails. `corpus/blind10/` contains ten
harder ones.

**An important caveat.** Those 50 emails were written for this project. The
analyser scores about 98% on them, which shows the reasoning holds up across
varied cases — but it is *not* a validated accuracy figure, because the same
person wrote the test and tuned the tool. A real number needs an independent
corpus: the **Nazario phishing corpus**, **SpamAssassin** (ham and spam), and
**Enron** (legitimate business mail) are the standard public sets.

---

## 9. Configuration reference

Everything is set in `.env`. Every setting has a safe default; the file only
exists to change them.

| Setting | Default | What it does |
|---|---|---|
| `PEA_HOST` | `127.0.0.1` | Network address. Leave as-is unless you know why |
| `PEA_PORT` | `8000` | Port |
| `PEA_DEBUG` | `false` | Verbose errors and API docs. Leave off |
| `PEA_HTTPS` | `false` | Set `true` behind HTTPS — marks cookies Secure |
| `PEA_DEFAULT_USERNAME` | `Vani` | First-run account |
| `PEA_DEFAULT_PASSWORD` | `Vani` | Leave blank to generate a random one instead |
| `PEA_LLM_API_KEY` | *(empty)* | AI key. Empty means rules-only |
| `PEA_AGENT_MODE` | `true` | AI investigates with tools vs single-shot |
| `PEA_PASSWORD_MIN_LENGTH` | `12` | For accounts created in the Users screen |
| `PEA_MAX_FAILED_LOGINS` | `5` | Failed logins before lockout |
| `PEA_LOCKOUT_MINUTES` | `15` | How long the lockout lasts |
| `PEA_MAX_UPLOAD_BYTES` | `2097152` | 2 MB upload limit |
| `PEA_ENABLE_URL_EXPANSION` | `false` | Follow links in analysed email — see below |
| `PEA_ENABLE_DNS_CHECKS` | `false` | Live DNS lookups |

### About the two network settings

`PEA_ENABLE_URL_EXPANSION` makes the analyser send requests to links found in
the emails you analyse — that is, to infrastructure controlled by whoever sent
the phishing. It is off by default for that reason.

It is safe when you do enable it: redirects are followed one hop at a time and
every hop is checked before the request is made, so a link cannot be used to
reach your own network. Nothing is ever rendered or executed — the page's HTML
is fetched, never run.

Still, it is an outbound connection from your machine to an attacker's server.
Turn it on deliberately, not by default.

---

## 10. Troubleshooting

**`python: command not found`**
Try `python3` instead. If neither works, install Python from python.org.

**`ModuleNotFoundError: No module named 'fastapi'`**
The virtual environment is not active. Run `source .venv/bin/activate`
(macOS/Linux) or `.\.venv\Scripts\Activate.ps1` (Windows), then
`pip install -r requirements.txt`.

**`Address already in use`**
Something is already on port 8000. Either stop it, or start on another port:
```bash
PEA_PORT=8001 python app.py
```

**The page loads but nothing happens when I click**
Hard refresh: `Ctrl+Shift+R` (or `Cmd+Shift+R` on Mac).

**"Too many failed attempts. Account locked"**
Wait 15 minutes, or delete `data/analyzer.db` to start completely fresh
(this erases all users and history).

**The AI layer says "rules-only" even though I set a key**
Check `.env` is in the project root, that the line has no spaces around `=`,
and restart the app. Then run `python main.py --probe`.

**Analysis is slow (10+ seconds)**
Your provider is rate-limiting and it is falling back to the slower one. This
is normal under bursts. `python main.py --probe` shows each provider's latency.

**I forgot the admin password**
Stop the app, delete `data/analyzer.db`, start it again. The default account
is recreated. This erases all history.

---

## 11. What is in the project

```
app.py                 web server and API routes
main.py                command-line interface
analyzer.py            the analysis pipeline

parser.py              raw email -> structured data
intel.py               brand list, phrase banks, homoglyph detection
headers_check.py       sender authentication and routing
urls_check.py          link analysis
content_check.py       social engineering and evasion
attachments_check.py   attachment analysis
netcheck.py            the only module that touches the network
scoring.py             evidence -> score, verdict, written assessment

agent.py               the investigating AI agent
tools.py               the tools the agent can call
llm.py                 provider-agnostic AI calls
fusion.py              combines both layers

security.py            passwords, sessions, rate limiting
db.py                  SQLite storage
auth.py                login and permissions

templates/ static/     the web interface (no build step)
tests/                 268 tests
samples/               7 demonstration emails
corpus/                50 + 10 labelled emails for measuring accuracy
regression.py          acceptance harness
evaluate.py            precision / recall / F1
selfcheck.sh           77 end-to-end checks
```

---

## 12. Safety notes

- Attachments are **never** opened, extracted or executed. They are identified
  by their file header and hashed, nothing more.
- Uploaded files are held in memory, analysed, and discarded. Nothing is
  written to disk.
- Email content is displayed as **text**, never rendered as HTML. A phishing
  email containing a script cannot run it in your browser.
- The database (`data/analyzer.db`) holds password hashes and your analysis
  history. It is created with owner-only permissions. Keep it out of any
  shared folder or backup you would not trust.
- If you enable the AI layer, the email body is sent to your chosen provider.
  Do not analyse confidential mail on a free tier without checking their data
  policy first.
