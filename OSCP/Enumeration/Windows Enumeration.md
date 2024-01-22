system arch  
x86は'x86', x64は'AMD64'または'x64'で返される
```
[System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE", [System.EnvironmentVariableTarget]::Process)
```

現在ログインしているユーザの情報  
```
whomai /all
```

