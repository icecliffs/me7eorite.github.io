# Filter(Servlet过滤器)

## 1.简介

**servlet过滤器**可以动态拦截请求和响应用来变换和使用在请求和响应中的信息。一个Servlet可以使用多个Filter即多个Servlet也可以使用同一个Filter同时也可以对静态、图片、html等文件进行过滤。

- Servlet过滤器可以实现的作用:
  - 在客户端请求访问后端资源之前拦截请求
  - 在服务器响应发送回客户端之前处理响应。

- 过滤器类型：
  - 身份验证过滤器
  - 数据压缩过滤器
  - 加密过滤器
  - 触发资源访问事件过滤器
  - 图像转换过滤器
  - 日志记录和审核过滤器
  - MIME-TYPE链过滤器
  - 标记化过滤器
  - XSL/T过滤器(转换XML内容)

## 2.Filter方法与实现

```java
public abstract interface Filter{
    public abstract void init(FilterConfig paramFilterConfig) throws ServletException;
  
    public abstract void doFilter(ServletRequest paramServletRequest, ServletResponse paramServletResponse, FilterChain 
        paramFilterChain) throws IOException, ServletException;
  
    public abstract void destroy();
}
```

| 方法                                                         | 描述                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `public void doFileter(ServletRequest,ServletResponse,FilterChain)` | 该方法完成实际的过滤操作，当客户端请求方法与过滤器设置匹配的URL时，Servlet容器将先调用过滤器的doFilter方法。FilterChain用户访问后续过滤器 |
| `public void init(FilterConfig filterConfig)`                | web应用程序启动时，web服务器将创建Filter的实例对象并调用其init方法，读取web.xml配置完成对象的初始化功能，从而为后续的用户请求做好拦截的准备工作(filter对象只会创建一个，init方法也只会执行一次)。开发人员通过init方法的参数，可以获得代表当前filter配置信息的FilterConfig对象 |
| `public void destroy()`                                      | Servlet容器在销毁过滤器实例前调用方法，在该方法中释放Servlet过滤器占用资源。 |

## 3.Filter工作原理

- 当Web服务器收到请求的时候，根据配置存在以下三种情况:
  - 调用`service()`前，执行`doFilter()`
  - 调用`service()`后，执行`doFilter()`
  - 不访问资源

当调用`doFilter()`时，传入一个`filterChain`实例它提供了一个`doFilter()`，我们可以根据需求判断是否执行该方法。如果调用``doFilter()`那么Web服务器就会去调用请求资源的`service()`。

## 4.Filter使用

### 4.1 自定义`Filter`类(需实现Filter接口)

```java
public class LoginFilter implements Filter {

    //获取初始化的参数，在这个方法中可以获取url路径/访问的资源路径...对不同的路径进行限制
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        //获取参数
        String site  = filterConfig.getInitParameter("Site");
        System.out.println("网站名称: "+site);
    }

    //主要的处理逻辑的方法
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        System.out.println("me7eorite");

        //将请求传回过滤链
        filterChain.doFilter(servletRequest,servletResponse);
    }

    @Override
    public void destroy() {

    }
}

```

主要还是在`doFilter()`中实现的，如果检验通过根据`filterChain.doFilter(servletRequest,servletResponse);`进行放行。

### 4.2 自定义XML文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

    <filter>
        <filter-name>LoginFilter</filter-name>
        <filter-class>LoginFilter</filter-class>
        <init-param>
            <param-name>Site</param-name>
            <param-value>me7eor1te</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>LoginFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    <servlet>
        <servlet-name>HelloWorld</servlet-name>
        <servlet-class>Main</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>HelloWorld</servlet-name>
        <url-pattern>/hello</url-pattern>
    </servlet-mapping>
</web-app>
```

#### 4.2.1 属性解释

- `filter`:定义一个过滤器
  - `filter-name`:为过滤器指定名字(不能为空)
  - `filter-class`:指定过滤器的类
  - `init-param`:为过滤器指定初始化参数
    - `param-name`:指定参数的名字
    - `param-value`:指定参数的值

在过滤器中可以使用FilterConfig接口对象访问初始化参数.例如:`FilterConfig.getInitParameter()`

- `filter-mapping`：用于设置一个Filter所负责拦截的资源。拦截方式：Servlet名称或者资源访问的请求路径
  - `filter-name`:设置filter的注册名称，该值必须是在`filter`标签中已经声明过的。
  - `url-pattern`:设置filter所拦截的请求路径(过滤器关联的URL样式)
- `servlet-name`:指定过滤器所拦截的Servlet名称
- `dispatcher`指定过滤器所拦截的资源被Servlet容器调用的方式，例如:REQUEST/INCLUDE/FORWARD/ERROR，其中REQUEST为默认方式。用户可以设置多个`dispatcher`子元素用来指定FIlter对资源的多种调用方式进行拦截。

### 4.3 Filter链(调用方式)

在一个Web应用中，如果我们**定义了多个Filter**那么这些Filter可以说**组成一条Filter链**，Web服务器根据Web.xml文件中**注册顺序决定调用**先那个Filter。

当第一个Filter的doFilter方法被时,会传递Web服务器生成的FilterChain对象当调用它的`doFilter()`Web服务器会判断是否还有filter。若有就调用，若没有就调用目标资源。

### 4.4 Spring自带Filter

```java
package org.springframework.web.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CharacterEncodingFilter extends OncePerRequestFilter {
    private String encoding;
    private boolean forceEncoding = false;

    public CharacterEncodingFilter() {
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public void setForceEncoding(boolean forceEncoding) {
        this.forceEncoding = forceEncoding;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (this.encoding != null && (this.forceEncoding || request.getCharacterEncoding() == null)) {
            request.setCharacterEncoding(this.encoding);
            if (this.forceEncoding) {
                response.setCharacterEncoding(this.encoding);
            }
        }

        filterChain.doFilter(request, response);
    }
}

```

### 4.5 使用配置

```xml
<filter>
    <filter-name>encodingFilter</filter-name>
    <filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
    <init-param>
        <param-name>encoding</param-name>
        <param-value>UTF-8</param-value>
    </init-param>
    <init-param>
        <param-name>forceEncoding</param-name>
        <param-value>true</param-value>
    </init-param>
</filter>

<filter-mapping>
    <filter-name>encodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

## 5.Filter生命周期

```
public interface Filter {
    void init(FilterConfig var1) throws ServletException;

    void doFilter(ServletRequest var1, ServletResponse var2, FilterChain var3) throws IOException, ServletException;

    void destroy();
}
```

### 5.1 创建

Filter创建和销毁都由WebServer决定，当Web应用启动时，WebServer出将创建Filter实例调用`init()`完成初始化。filter只创建一次也就是说`init()`只调用一次，

### 5.2 销毁

WebServer调用`destroy()`销毁Filter对象。该方法也只执行一次。

### 5.3 `FilterConfig`

自定义配置filter时，通过`init-param`可以为了filter配置初始化参数，当Web容器实例化Filter对象调用init方法时会把封装了filter初始化参数的filterConfig对象传递进去。

```java
public interface FilterConfig {
    String getFilterName(); //获取filter名称

    ServletContext getServletContext(); //获取servlet上下文对象引用
 
    String getInitParameter(String var1); //获取初始化参数名称，不存在返回null
 
    Enumeration<String> getInitParameterNames(); //获取过滤器的所有初始化参数的名字的枚举集合
}
```







