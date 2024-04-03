# JNDI总结

## 1.JNDI

**JNDI(Java Naming Direcorty Interface) Java命令和目录接口**：一组应用程序接口，为开发人员查找和访问各种资源提供了统一的通用接口，可以用来定义 用户、网络、机器、对象和服务等。

- JNDI支持的服务：
  - RMI
  - LDAP
  - DNS
  - CORBA

简单来说，JNDI是一组API接口，每个对象都有一组唯一的键值对绑定，将名字和对象进行绑定，通过名字来检索指定的对象而对象可能存储在RMI、LDAP、CORBA中。

<img src="img/1647331551948-b6806bd3-c1be-4330-9816-694f6379340a-20230120154437240.png" alt="img"  />







## 2.远程代码和安全管理器







## 3.JNDI注入







## 4.绕过高版本JDK