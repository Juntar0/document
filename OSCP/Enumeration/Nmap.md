## Initial Scan  
-Pnでping sweep禁止、-AはデフォルトでOS検出(`-O`)とバージョンスキャン(`-sV`)が含まれる
```
sudo nmap -Pn -A -T4 -oN OUTPUT IP
```
## Port Scan  
-pでポート指定
```
sudo nmap -p PORT IP
```

複数ポート
```
sudo nmap -p 80,443 IP
```

レンジ指定
```
sudo nmap -p 0-1024 IP
```

## 