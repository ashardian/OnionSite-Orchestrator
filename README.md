
# 🧅 OnionSite-Orchestrator
### Advanced Tor Hidden Service Deployment Tool for Debian/Parrot OS

**OnionSite-Orchestrator** is an **industry-grade**, fully automated Bash tool designed to deploy and manage a secure Tor Hidden Service (Onion website) on **Debian-based Linux systems**.  
It automatically installs, configures, and maintains **Tor**, **Nginx**, **UFW firewall**, and your onion site — with built-in **error recovery**, **self-healing**, **status validation**, and **security hardening**.

---

## 🚀 Features

✅ **One-command setup** — fully automated installation and configuration  
✅ **Automatic Tor + Nginx orchestration**  
✅ **Self-healing** — detects and fixes Tor/Nginx misconfigurations automatically  
✅ **Secure defaults** — serves your site only via localhost and Tor  
✅ **Firewall integration (UFW)** — blocks all inbound traffic except SSH  
✅ **Onion hostname generation** — no manual configuration required  
✅ **Automatic restart and recovery** if Tor or Nginx stop unexpectedly  
✅ **Detailed logging** — view full logs in `/var/log/onionsite-orchestrator.log`  
✅ **Custom webroot detection and repair**  
✅ **Industry-level security hardening**  
✅ **Works out of the box on Debian 11+, Parrot OS, and Ubuntu 22.04+**

---

## 🧩 Requirements

- Debian / Ubuntu / Parrot OS  (Tested on Debain)
- Root or `sudo` privileges  
- Active network connection  
- `apt`, `systemd`, and `bash` available (default on Debian-based distros)

---

## ⚙️ Installation

### 1️⃣ Clone or Download
```bash
git clone https://github.com/<your-username>/onionsite-orchestrator.git
cd onionsite-orchestrator
````

### 2️⃣ Make the script executable

```bash
chmod +x onionsite-orchestrator.sh installer.sh
```

### 3️⃣ Run the installer (auto-configures everything)

```bash
sudo ./installer.sh
```

This installs the orchestrator globally to:

```
/usr/local/bin/onionsite-orchestrator.sh
```

---

## 🧠 Usage

### 🏗️ Initial Setup

```bash
sudo onionsite-orchestrator.sh --install
```

This command will:

* Install all required packages (`tor`, `nginx`, `ufw`, `openssl`, etc.)
* Configure a secure Nginx instance on localhost
* Set up a hidden Tor service at `/var/lib/tor/onion_service`
* Auto-create a sample website at `/var/www/onion_site`
* Print your new `.onion` address at the end

---

### 🔍 View Onion Address

```bash
sudo onionsite-orchestrator.sh --show-address
```

---

### 💡 Self-Heal / Repair Service

If your Onion site fails to load in the Tor browser:

```bash
sudo onionsite-orchestrator.sh --self-heal
```

This feature automatically:

* Checks Tor logs and restarts it if needed
* Validates Tor control and SOCKS5 ports (9050, 9051)
* Repairs `/etc/tor/torrc` configuration
* Verifies Nginx binding to `127.0.0.1:8080`
* Regenerates hidden service if corrupted
* Reconfirms onion hostname availability

---

### 🧱 Firewall Configuration

```bash
sudo onionsite-orchestrator.sh --firewall
```

This resets and configures UFW with:

* `deny incoming`
* `allow outgoing`
* `allow ssh`

---

### 📊 Service Status

```bash
sudo onionsite-orchestrator.sh --status
```

Shows:

* Tor/Nginx running state
* Active `.onion` address
* Listening ports
* UFW firewall rules
* Log file path

---

### 🗑️ Uninstall Everything

```bash
sudo onionsite-orchestrator.sh --uninstall
```

This removes:

* Tor hidden service
* Nginx site configuration
* Web root files
* UFW rules created by the tool
* Log files and orchestrator binary

---

## 🪪 Example Output

```
[2025-11-02T13:00:16Z] [INFO] Tor: active
[2025-11-02T13:00:16Z] [INFO] nginx: active
[2025-11-02T13:00:16Z] [INFO] Onion hostname created: http://evk4qkbycx2gx5oxthrjynsjziqttqnne5xo6v6zanhtlid.onion
[2025-11-02T13:00:16Z] [INFO] Web server reachable at 127.0.0.1:8080
[2025-11-02T13:00:16Z] [INFO] Access your onion site using Tor Browser:
       http://evk4qkbycx2gx5oxthrjynsjziqttqnne5xo6v6zanhtlid.onion
```

---

## 🔒 Security Notes

* The site only listens on **localhost (127.0.0.1)** for maximum isolation.
* **No clearnet access** — it’s only available over Tor.
* The script applies **best practices** for Tor hidden service deployment:

  * Disables directory indexing
  * Denies framing (anti-clickjacking)
  * Enforces MIME type consistency
  * Uses restrictive UFW rules
* You can further harden it by enabling **AppArmor** or **SELinux** profiles.

---

## 🧾 Logs & Diagnostics

All actions are logged to:

```
/var/log/onionsite-orchestrator.log
```

To inspect real-time logs:

```bash
sudo tail -f /var/log/onionsite-orchestrator.log
```

---

## 💬 Troubleshooting

| Problem                       | Solution                                         |
| ----------------------------- | ------------------------------------------------ |
| `.onion` site not loading     | Run `sudo onionsite-orchestrator.sh --self-heal` |
| Tor service stops             | `sudo systemctl restart tor`                     |
| No `.onion` address generated | Check `/var/lib/tor/onion_service/hostname`      |
| Nginx fails to reload         | Run `nginx -t` to test config                    |
| Firewall blocking Tor         | Run `sudo onionsite-orchestrator.sh --firewall`  |

---

## 🛡️ Recommended Enhancements

* Enable **HTTPS over Onion** using a self-signed SSL cert
* Add **.onion v3 key backup** and rotation management
* Integrate **Fail2Ban** for SSH protection
* Periodic self-check cron job (`--auto-repair` mode)

---

## 🤝 Contributing

1. Fork this repo
2. Create a new feature branch
3. Submit a PR with detailed description

Bug reports and suggestions are always welcome!

---

## 🧾 License

This project is released under the **MIT License**.
See `LICENSE` for more details.

---

## 👨‍💻 Author

**OnionSite-Orchestrator** by Ashar Dian
Built for privacy enthusiasts, researchers, and developers who value secure web hosting over Tor.

```
