# FalconHunter - Active Recon & Vulnerability Scanner  

**FalconHunter** is a hands-on security tool built for pentesters and security researchers. It helps you dig into targets, find weaknesses, and get the data you need—fast.  

## Why Use This?

* **Tool Integration**: Leverages a wide array of tools like `httpx`, `nuclei`, `dnsx`, `subfinder`, and `cname finder` to automate the reconnaissance process.
* **Logging Support**: Includes a logging system to track scan progress and results, making debugging and auditing easier.
* **Telegram Bot Alerts**: Optionally integrates with Telegram to send real-time updates or final scan results directly to your chat.
* **Modular & Customisable**: Easily tweak which tools or modules to run, based on your recon scope or target type. 

## Get It Running  

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

## How to Use It 

Add your telegram bot API token to `config.yaml`:

```yaml
telegram:
  token: "your_bot_token"
  chat_id: "your_chat_id"

cleanup:
  remove_empty_files: true
  remove_empty_dirs: true

```


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

**GitHub**: [https://github.com/OctaYus/FalconHunter](https://github.com/OctaYus/FalconHunter)  

---  
*Built for those who break things to make them secure.*
