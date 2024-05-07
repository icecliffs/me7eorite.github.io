# CodeQL总结

## 1.环境搭建

官方文档推荐使用vscode extension来搭建CodeQL环境，简单来说就是下面三个步骤：

- 下载CodeQL CLI命令行工具，配置好终端环境变量

  ```
  brew install codeql
  ```

- vscode安装CodeQL插件，配置好CodeQL CLI的路径

  - 在vscode插件市场寻找就可以。

- 下载vscode-codeql-starter工作空间

  ```
  git clone https://github.com/github/codeql.git
  ```

创建数据库

```
codeql database create /Users/me7eorite/Documents/Team/Tools/Exp/Java/CodeQL/databases/java-sec-code --language=java --source-root=/Users/me7eorite/Documents/Java/java-sec-code --command="mvn clean package"
```

## 2.基础语法