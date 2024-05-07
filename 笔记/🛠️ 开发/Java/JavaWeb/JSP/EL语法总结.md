# EL表达式

## 1.基础语法

- El表达式表达属性值的方式:

```jsp
${expr}
```

- El表达式能够引用的对象:
  - Lambda 
  - El
  - Managed beans
  - Implicit objects
  - Classes of static fields and methods

引用对象属性或者集合元素,可以使用`.`或者`[]`表示

```java
${customer.name}
${customer["name"]}//在[]之中的也可以是字符串表达式或者动态取值
${customer["abc","name"][1]}
```

### 1.1 判断和比较

比较方式都是双等==,表达式之中并没有equals。

**判断对象是否为空:**

```java
${empty 对象名}
${对象名 == null}
```

对空值的处理并不显示,`${变量名}`当该变量为空获取不到值的时候不显示。

表示中不能有Java代码且运算只能数字+数字，el中没有++和--

## 2.操作符

- **常见操作符**

  | 类型   | 符号                                           |
  | ------ | ---------------------------------------------- |
  | 算术型 | +、-、*、/、div、%、mod、-                     |
  | 逻辑型 | and、&&、or、\|\|、！、not                     |
  | 关系型 | ==、eq、!=、ne、<、lt、>、gt、<=、le、>=、ge。 |
  | 条件   | 三目运算符 a?b:c                               |
  | 空     | empty 用来判断是否为空                         |

  

- **运算符优先级**(从高到低、从左到右)

  1. `[] .`

  2. `()`:可以用来更改运算符优先级
  3. `-、not ! empty`
  4. `* / div % mod`
  5. `+ -`
  6. `+=`
  7. `<> <= >= lt gt le ge`
  8. `== != eq ne`
  9. `&& and`
  10. `|| or`
  11. `? :`(三目运算符)
  12. `->`
  13. `=`
  14. `;`

- **保留运算符**

  - true
  - false
  - null
  - instanceof
  - empty
  - div
  - mod

## 3.函数

**使用函数**

```java
${ns:func(param1,param2,...)}
```

**调用Java函数**

创建一个类

```java
public class ELFunc{
  public static String hell(String s){
    return s;
  }
}
```

创建一个xld

```xml
<?xml version="1.0" encoding="utf-8" ?>
<taglib xmlns="http://java.sun.com/xml/ns/j2ee"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-jsptaglibrary_2_0.xsd">
    <tlib-version>1.0</tlib-version>
    <short-name>ELFunc</short-name>
    <uri>http://www.me7eorite.com/ELFunc</uri>
    <function>
        <name>hello</name>
        <function-class>ELFunc</function-class>
        <function-signature>java.lang.String hello(java.lang.String)</function-signature>
    </function>
</taglib>
```

jsp使用的语法

```jsp
<%@ page contextType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="ELFunc" uri="http://www.test.com/ELFunc" %>

${ELFunc:hello("hello world")}
```



## 4.隐含对象

| 隐含对象         | 描述                                                         | 使用方式                           |
| ---------------- | ------------------------------------------------------------ | ---------------------------------- |
| pageContext      | page作用域.PageContext实例对应于当前页面的处理。pageContext对象是JSP中pageContext对象的引用，通过pageContext对象可以访问request对象 | ${pageContext.request.queryString} |
| requestScope     | request作用域.与请求作用域属性的名称和值相关量的Map类        |                                    |
| sessionScope     | session作用域.与会话作用域属性的名称和值相关联的Map类        |                                    |
| applicationScope | application作用域.与应用程序作用域的名称和值相关联的Map类    |                                    |
| param            | 按名称存储请求参数的主要值Map类                              |                                    |
| paramValues      | 将请求参数的所有值作为String数组存储的Map类                  |                                    |
| headerValues     | 将请求投的所有值作为String数组存储的Map类                    |                                    |
| initParam        | 按名称存储Web应用程序上下文初始化参数的Map类                 |                                    |
| cookie           | 按名称存储请求附带cookie的Map类                              |                                    |
| header           | 按名称存储请求头主要值的Map类                                |                                    |
|                  |                                                              |                                    |

JSP存在9个隐式对象:

| request     | HttpServletRequest接口的实例                                |
| ----------- | ----------------------------------------------------------- |
| response    | HttpServletResponse接口的实例                               |
| out         | JspWriter类的实例，用于把结果输出到网页上                   |
| session     | HttpSession类的实例                                         |
| application | ServletContext类的实例与应用上下文有关                      |
| config      | ServletConfig类的实例                                       |
| pageContext | PageContext类的实例,提供对Jsp页面所有对象以及命名空间的访问 |
| page        | 类似于Java类中的this关键字                                  |
| Exception   | Exception类的对象，代表发生错误的Jsp页面中对应的异常对象。  |

## 5.EL表达使用

当在jsp需要使用el表达式调用函数的时候需要用taglib引入标签库

**启动/禁用EL表达式**

**全局禁用EL表达式**

```xml
<jsp-config>
	<jsp-property-group>
    <url-pattern>*.jsp</url-pattern>
    <el-ignored>true</el-ignored>
  </jsp-property-group>
</jsp-config>
```

单个文件禁用EL表达式,True表示禁止、False表示不禁止

```jsp
<%@ page isELIgnored="true" %>
```

