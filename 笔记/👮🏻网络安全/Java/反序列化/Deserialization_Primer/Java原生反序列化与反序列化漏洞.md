# Java原生反序列化与反序列化漏洞

## 1.序列化与反序列化

> - 序列化分为两大部分：序列化和反序列化。
>
>   - **序列化**：是这个过程的第一部分，将数据分解成字节流，以便存储在文件中或在网络上传输。
>
>   - **反序列化**：是打开字节流并重构对象。对象序列化不仅要将基本数据类型转换成字节表示，有时还要恢复数据。恢复数据要求有恢复数据的对象实例。
>
> - 总结：
>
>   - **Java序列化**:把Java对象转换为字节序列的过程。
>
>   - **Java反序列化**:把字节序列恢复为Java对象的过程。



> **为什么需要序列化与反序列化？**
>  我们知道，当两个进程进行远程通信时，可以相互发送各种类型的数据，包括文本、图片、音频、视频等， 而这些数据都会以二进制序列的形式在网络上传送。那么当两个Java进程进行通信时，能否实现进程间的对象传送呢？答案是可以的。如何做到呢？这就需要Java序列化与反序列化了。换句话说，一方面，发送方需要把这个Java对象转换为字节序列，然后在网络上传送；另一方面，接收方需要从字节序列中恢复出Java对象。
>
>  当我们明晰了为什么需要Java序列化和反序列化后，我们很自然地会想Java序列化的好处。其好处一是实现了数据的持久化，通过序列化可以把数据永久地保存到硬盘上（通常存放在文件里），二是，利用序列化实现远程通信，即在网络上传送对象的字节序列。
>
> ① 想把内存中的对象保存到一个文件中或者数据库中时候；
> ② 想用套接字在网络上传送对象的时候；
> ③ 想通过RMI传输对象的时候

## 2.代码实现

由于序列化的操作单位是对象，所以我们需要先构造一个User实体类，部分代码([完整代码](https://github.com/Me7eorite/Learning-Demo/blob/main/JavaStudy/src/main/java/com/learning/serialization/primer/User.java))内容如下：

```java
public class User implements Serializable { //只有实现了Serializable或者Externalizable接口的类的对象才能被序列化为字节序列。
    private int id;
    private String name;
    private String pass;

    public User() {
    }
    ...
}
```

在上述代码中，`Serializable`接口的代码如下：

```java
public interface Serializable {
}
```

它是Java提供的序列化接口，一个空接口，用来作为类是否可序列化与反序列化的标识。



## 参考文章

[java序列化与反序列化全讲解](https://blog.csdn.net/mocas_wang/article/details/107621010)