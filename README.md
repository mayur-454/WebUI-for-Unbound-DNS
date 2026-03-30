# WebUI for Unbound DNS

>[!WARNING]
>AI Disclosure: This project was developed entirely using AI. The creator is not a Python or Java programmer. Use at your own risk. The creator is not responsible for data loss or system instability.

https://camo.githubusercontent.com/2e445a865a4b6368b5fe5fdd90deb88311469c644320af29c1499ab42b506884/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f706c6174666f726d2d4c696e75782d4643433632343f6c6f676f3d6c696e7578266c6f676f436f6c6f723d626c61636b

<details open>
  <summary><b>Click to collapse Screenshots</b></summary>
  <br>

  **Home Page:**
  <img width="1495" height="1186" alt="image" src="https://github.com/user-attachments/assets/1bcaf0d8-02d5-4980-ad23-ef0595acf326" />

  **Config Page:**
  <img width="1495" height="1186" alt="image" src="https://github.com/user-attachments/assets/987ed7cf-5590-4890-aab7-614415d62dc7" />

  **Debug Page:**
  <img width="1495" height="1186" alt="image" src="https://github.com/user-attachments/assets/8bb9823e-1349-4998-b308-3937e151ebec" />

  **Settings Page:**
  <img width="1495" height="1186" alt="image" src="https://github.com/user-attachments/assets/a7ac70aa-1a5a-4306-bd7a-cb10dbcea26d" />

  **Login Page:**
  <img width="1495" height="1186" alt="image" src="https://github.com/user-attachments/assets/d73153fd-3139-4891-be51-4770413cd4a8" />

</details>




# Setup Guide   
Follow these steps to set up the environment and run the Unbound DNS WebUI.   
## 1. Prerequisites   
First, ensure that `pip` and the `venv` package are installed on your system.   
```
# Update package list and install pip
sudo apt install python3-pip

# Install the virtual environment package
sudo apt install python3-venv
```
## 2. Environment Setup   
It is recommended to use a virtual environment to manage your dependencies and keep your system clean.   
```
# Create a virtual environment named 'venv'
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
```
Once activated, you will see `(venv)` prepended to your terminal prompt.   
## 3. Installing Dependencies   
Inside the activated virtual environment, install the required Python packages:   
```
# Install FastAPI with standard dependencies
pip install "fastapi[standard]"

# Install the itsdangerous module for security
pip install itsdangerous
```
### Optional: TLS Support (HTTPS)   
If you are using a reverse proxy (like **Nginx**), you do not need to install the `cryptography` package, as the proxy typically handles **TLS termination**. In this setup, the WebUI will be accessible via HTTP on port `8080`.   
However, if you are **not** using a proxy and want to use HTTPS directly (highly recommended), you must install the `cryptography` package. This allows the application to generate and manage self-signed TLS certificates:   
```
pip install cryptography
```
## 4. Launching the Application   
Run the application using Python. On the first launch, if `cryptography` is installed, the system will automatically generate a self-signed TLS certificate.   
```
python app.py
```
**Example Output:**   
```
(venv) root@server:~/WebUI-for-Unbound-DNS# python app.py
[ssl] Generating self-signed TLS certificate…
[ssl] Certificate written to /root/WebUI-for-Unbound-DNS/ssl_cert.pem
[ssl] Private key written to /root/WebUI-for-Unbound-DNS/ssl_key.pem (chmod 600)
[ssl] Valid for 3650 days
[http-redirect] 8080 → https://...:8443
[app] HTTPS on [https://0.0.0.0:8443](https://0.0.0.0:8443)
```
## 5. Accessing the Web UI   
Once the application is running:   
- **With TLS/HTTPS:** Access the interface at `https://<your-ip>:8443`.   
- **Without TLS/HTTP:** Access the interface at `http://<your-ip>:8080`.   
   
> Note: If you are using a self-signed certificate, your browser will display a "Potential Security Risk" warning. This is expected behavior; you can safely click "Advanced" and "Proceed" to access your local interface.   

