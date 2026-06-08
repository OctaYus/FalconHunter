# FalconHunter - Active Recon & Vulnerability Scanner  

**FalconHunter** is a hands-on security tool built for pentesters and security researchers. It helps you dig into targets, find weaknesses, and get the data you need—fast.  

## Why Use This?

* **Tool Integration**: Leverages a wide array of tools like `httpx`, `nuclei`, `dnsx`, `subfinder`, and `cname finder` to automate the reconnaissance process.
* **Logging Support**: Includes a logging system to track scan progress and results, making debugging and auditing easier.
* **Telegram Bot Alerts**: Optionally integrates with Telegram to send real-time updates or final scan results directly to your chat.
* **Modular & Customisable**: Easily tweak which tools or modules to run, based on your recon scope or target type. 

## Get It Running  

### Option 1 — `go install` (Recommended)

If you have Go 1.22+ installed, grab the binary in one line:

```bash
go install github.com/OctaYus/FalconHunter/cmd/falcon@latest
```

This drops the `falcon` binary into `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Then run it:

```bash
falcon -h
```

### Option 2 — Build from source

1. **Grab the code**:  
   ```bash
   git clone https://github.com/OctaYus/FalconHunter.git
   cd FalconHunter
   ```  

2. **Install dependencies (just run this)**:  
   ```bash
   pip install -r requirements.txt
   bash install.sh
   ```  

3. **Build the binary**:  
   ```bash
   go build -o falcon ./cmd/falcon
   ```  

## Updating

Once you're on a recent build, updating is one command — it checks GitHub directly and self-updates from any directory:

```bash
falcon -up
```

It compares the commit baked into your binary against the latest on `main`. If you're behind, it pulls and rebuilds in place (inside a clone) or `go install`s the newest commit straight from GitHub.

### Coming from an older version (one-time manual reinstall)

Older binaries don't have `-up`, so do this once:

1. **Remove the old binary** (check every location first):
   ```bash
   type -a falcon                       # lists all copies on your PATH
   rm -f ~/go/bin/falcon /usr/local/bin/falcon ~/.local/bin/falcon
   ```

2. **Install the latest** — tip of `main`, no module-proxy lag:
   ```bash
   GOPROXY=direct go install github.com/OctaYus/FalconHunter/cmd/falcon@main
   ```
   *(or clone + build: `git clone https://github.com/OctaYus/FalconHunter && cd FalconHunter && go build -o ~/go/bin/falcon ./cmd/falcon/`)*

3. **Install the JS-analysis dependencies** the new version uses:
   ```bash
   go install github.com/BishopFox/jsluice/cmd/jsluice@latest
   go install github.com/OctaYus/depfusion@latest
   # or just re-run: bash install.sh
   ```

4. **Verify:**
   ```bash
   which falcon && falcon -h | grep -E "mantra|update"
   ```

After that, every future update is just `falcon -up`.

## Notification Setup (Telegram, Discord, Slack)

FalconHunter can send real-time alerts via Telegram, Discord, and Slack. Credentials are read from environment variables first, then from `config.yaml` as a fallback.

### Option A — Environment Variables (Recommended)

Keeps secrets off disk and out of version control.

**For the current terminal session only** (lost when you close the terminal):
```bash
export TELEGRAM_TOKEN="7123456789:AAFxxx..."
export TELEGRAM_CHAT_ID="123456789"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

**To make them permanent** (survive reboots and new terminal sessions):

1. Open your shell config file:
   ```bash
   nano ~/.bashrc        # if you use bash
   # or
   nano ~/.zshrc         # if you use zsh
   ```
2. Add these lines at the bottom:
   ```bash
   export TELEGRAM_TOKEN="7123456789:AAFxxx..."
   export TELEGRAM_CHAT_ID="123456789"
   export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
   ```
3. Save and apply the changes:
   ```bash
   source ~/.bashrc      # or source ~/.zshrc
   ```
4. Verify they are set:
   ```bash
   echo $TELEGRAM_TOKEN
   echo $TELEGRAM_CHAT_ID
   ```

### Option B — config.yaml (Fine for local/private use)

Edit `config.yaml` directly:

```yaml
telegram:
  token: "your_bot_token"
  chat_id: "your_chat_id"

discord:
  webhook_url: "https://discord.com/api/webhooks/..."

slack:
  webhook_url: "https://hooks.slack.com/services/..."
```

> **Do not commit real tokens to git.** If you use Option B, add `config.yaml` to your `.gitignore` or keep the values empty and use env vars instead.

### How to get your Telegram credentials

**Step 1 — Create a bot and get the token**
1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Give your bot a name (e.g. `FalconHunter Alerts`)
4. Give your bot a username ending in `bot` (e.g. `falconhunter_bot`)
5. BotFather replies with your token — looks like `7123456789:AAFxxx...`
6. Copy that — that is your `TELEGRAM_TOKEN`

**Step 2 — Get your chat ID**
1. Search for your new bot in Telegram and press **Start** (or send it any message)
2. Open this URL in your browser (replace `<YOUR_TOKEN>` with the token from Step 1):
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
3. Look for `"chat":{"id":` in the JSON response — the number after it is your `TELEGRAM_CHAT_ID`
4. Example response:
   ```json
   {"message":{"chat":{"id": 123456789, "type":"private"}, ...}}
   ```
   So `TELEGRAM_CHAT_ID` would be `123456789`

**Step 3 — Test it works**

Run this in your terminal (replace the placeholders):
```bash
curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/sendMessage?chat_id=<YOUR_CHAT_ID>&text=FalconHunter+connected"
```
If you get a JSON response with `"ok":true`, it's working.

---

## How to Use It

Basic scan:  
```bash
python3 main.py -d example_list.txt -o results.txt
```  
Need help? Run:  

```bash
python3 main.py -h

options:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        Path to file containing list of domains
  -o OUTPUT, --output OUTPUT
                        Output directory name
```  

## Contribute  

Found a bug? Got a killer feature idea?  
- Open an **issue**  
- Send a **pull request**  
- No BS—just practical improvements  

## License  

**MIT License** - Do what you want, just don't blame us.  
