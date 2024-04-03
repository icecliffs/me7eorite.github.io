# FastJson1.2.22-1.2.24 反序列化分析

## 1.漏洞原理

FastJson 反序列化是因为未对`@type`字段进行有效的校验导致可以传入恶意的类且反序列化的时候会自动调用`setter`和无参构造器，在某些情况下会调用`getter`，当这些方法存在利用点的时候，我们通过传入可控利用点成员变量进行攻击利用。

Fastjson通过parse、parseObject处理以json结构传入的类的字符串形时，会默认调用该类的共有setter与构造函数，并在合适的触发条件下调用该类的getter方法。当传入的类中setter、getter方法中存在利用点时，攻击者就可以通过传入可控的类的成员变量进行攻击利用







## 2.利用分析

### 2.1 TemplateImpl





### 2.2 JdbcRowSetImpl
