# gsma-rsp-available-checker

This project can detect CI supported by rsp server

```text
python main.py -s <server URL> -c <certificate name id> [-w <saved file name>]
```

This return value represents connection exception or WAF interception

````json
{
   "status": "error"
}
````

This return value means that the server is connected and does not support this certificate.

````json
{
   "status": "fail"
}
````

This return value represents a normal return

````json
{
   "status": "success",
   "cert": "MIICtzCCAl2..."
}
````

# 中文版本
这个项目可以检测rsp服务器支持的CI

```text
python main.py -s <服务器URL> -c <证书名id> [-w <保存的文件名>]
```

这个返回值代表 连接异常 或 WAF拦截

````json
{
  "status": "error"
}
````

这个返回值代表 连上了 服务器不支持这个证书

````json
{
  "status": "fail"
}
````

这个返回值代表正常返回

````json
{
  "status": "success",
  "cert": "MIICtzCCAl2..."
}
````