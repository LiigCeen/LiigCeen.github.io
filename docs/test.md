## 代码执行漏洞

> java是编译型语⾔，该漏洞主要是指脚本引擎代码注⼊。Java的`javax.script.ScriptEngineManager`类的`eval函数`可以被控制⽤于执⾏代码
>
> 利用范围：低于jdk1.8

**代码示例**

```java
@ApiOperation(value = "vul：代码注入 - 脚本引擎", notes = "调用远程js脚本程序进行封装")
@GetMapping("/vul")
public String jsEngine(String url) {
    try {
        // 通过脚本名称获取
        // ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

        // 通过文件扩展名获取
        ScriptEngine engine = new ScriptEngineManager().getEngineByExtension("js");

        // Bindings：用来存放数据的容器
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        String payload = String.format("load('%s')", url);
        engine.eval(payload, bindings);
        return "漏洞执行成功";
    } catch (Exception e) {
        return "加载远程脚本: " + HtmlUtils.htmlEscape(url);
    }
}
```



**代码分析**

1. **`public String jsEngine(String url)`**:
   - 该方法接受一个`url`参数，用户通过GET请求传入。该`url`是远程JavaScript文件的地址，后续代码会通过这个`url`加载并执行JavaScript脚本。

2. **`ScriptEngine engine = new ScriptEngineManager().getEngineByExtension("js");`**:
   - 这行代码创建了一个JavaScript脚本引擎。`ScriptEngineManager`可以根据语言名称、文件扩展名或者MIME类型来获取相应的脚本引擎。在此，代码通过文件扩展名`"js"`获取JavaScript的脚本引擎。

3. **`Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);`**:
   - `Bindings`是一个容器，用来存储脚本执行时的变量或数据。在这里创建了一个绑定器，用于存储脚本执行过程中需要的数据。

4. **`String payload = String.format("load('%s')", url);`**:

   - `payload`是构造的JavaScript表达式，形式为`load('<url>')`。`load()`函数会加载并执行指定URL的JavaScript文件。

   - `url`是用户提供的参数，因此攻击者可以传递恶意的URL，执行从该URL加载的恶意JavaScript代码。

5. **`engine.eval(payload, bindings);`**:

   - 这一行通过脚本引擎执行构造的`payload`，即通过`eval()`方法执行JavaScript代码。在这里，JavaScript脚本引擎会下载并执行`url`指向的脚本文件。

   - 由于`url`的内容是用户可控的，攻击者可以提供恶意的远程脚本并使其在服务器上执行，从而导致远程代码执行漏洞。

6. **异常处理**：
   - 如果脚本执行过程中出现异常，例如无法加载脚本，异常将被捕获，并返回处理后的错误消息，其中对`url`进行了HTML转义，以防止XSS攻击。



**存在漏洞的原因**

* **不受信任的输入**：`url`参数是由用户控制的，攻击者可以传递恶意的JavaScript文件URL，从而在服务器端执行任意JavaScript代码。

* **缺乏输入验证和过滤**：代码没有对`url`参数进行任何验证，直接使用该URL加载并执行脚本。攻击者可以通过精心构造的URL加载恶意代码。

* **`eval()`滥用**：`eval()`函数本质上是危险的，因为它可以执行任意代码。在此代码中，`eval()`直接执行了从远程URL加载的内容，进一步加剧了风险。



## 表达式注入

> java语言方面的表达式主要包括以下：
>
> SpEL表达式 --Spring
>
> OGNL表达式 -- Struts2、Confluence
>
> Groove表达式



### SpEL注入

**代码样例**

```java
@GetMapping("/vul")
public String vul1(String ex) {
    ExpressionParser parser = new SpelExpressionParser();

    // StandardEvaluationContext权限过大，可以执行任意代码，默认使用可以不指定
    EvaluationContext evaluationContext = new StandardEvaluationContext();
    Expression exp = parser.parseExpression(ex);

    String result = exp.getValue(evaluationContext).toString();
    log.info("[vul] SpEL");
    return result;
}
```

**代码分析**

1. **`public String vul1(String ex)`**:
   - 这个方法接收一个名为`ex`的字符串参数，通常是通过HTTP GET请求传递的。用户可以通过URL参数直接控制该变量的值。

2. **`ExpressionParser parser = new SpelExpressionParser();`**:
   - `SpelExpressionParser`是Spring中的表达式解析器，专门用于解析和执行SpEL表达式。

3. **`EvaluationContext evaluationContext = new StandardEvaluationContext();`**:
   - 创建了一个`StandardEvaluationContext`对象，它用来存储和管理SpEL表达式执行的上下文。在这种情况下，`StandardEvaluationContext`权限较大，能够提供对大量Java对象和方法的访问。

4. **`Expression exp = parser.parseExpression(ex);`**:
   - 使用`parser`解析用户传入的`ex`字符串，将其转换为SpEL表达式。

5. **`String result = exp.getValue(evaluationContext).toString();`**:

   - 通过`exp.getValue(evaluationContext)`在特定的上下文环境中执行用户提供的表达式，并将其结果转换为字符串。

   - 由于`StandardEvaluationContext`权限较大，这允许执行任意Java方法调用，例如调用系统命令、访问文件系统等。

poc:`T(java.lang.Runtime).getRuntime().exec("calc")` 

**漏洞产生原因**

1. **用户输入未正确验证**：当用户的输入数据直接作为SpEL表达式的一部分时，如果没有进行严格的校验和过滤，攻击者可以构造恶意的表达式提交。

2. **动态执行表达式**：SpEL支持执行动态表达式，包括访问对象属性、方法调用，甚至可以执行任意代码。如果用户输入控制了这些表达式，就有可能利用这些功能执行恶意代码。



### OGNL注入

**代码样例**

```java
import ognl.Ognl;
import ognl.OgnlContext;
public class Test {
    public static void main(String[] args) throws Exception {
    // 创建⼀个OGNL上下⽂对象
    OgnlContext context = new OgnlContext();
    // getValue()触发
    // @[类全名(包括包路径)]@[⽅法名|值名]
    Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context, context.getRoot());
    
    // setValue()触发
    // Ognl.setValue(Runtime.getRuntime().exec("calc"), context, contex
    t.getRoot());
    }
}
```

**代码分析**

1. **`OgnlContext context = new OgnlContext();`**：
   - 创建一个`OgnlContext`上下文对象。这个上下文对象用于存储变量、表达式结果，并提供OGNL表达式的执行环境。

2. **`Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context, context.getRoot());`**：

   - 这是一个通过OGNL执行表达式的方法调用。表达式`"@java.lang.Runtime@getRuntime().exec('calc')"`通过OGNL执行，含义如下：
     - `@java.lang.Runtime`：表示调用Java的`Runtime`类。
     - `@getRuntime()`：调用`Runtime`类的静态方法`getRuntime()`，返回`Runtime`的实例。
     - `exec('calc')`：调用`Runtime`实例的`exec()`方法来执行系统命令`calc`（打开计算器）。

   - 通过`Ognl.getValue()`方法，OGNL解析并执行了这段表达式。这实际上在系统上执行了命令`calc`，从而打开了计算器程序。

**OGNL注入的原理**

OGNL注入类似于其他注入攻击（如SQL注入或命令注入），攻击者通过构造恶意的输入数据，试图在服务器端执行任意代码。当应用程序直接将用户输入嵌入到OGNL表达式中时，攻击者可以利用OGNL语法来构建恶意表达式，从而执行任意代码或获取敏感数据。例如`@java.lang.Runtime@getRuntime().exec('calc')`



## SSTI模板注入（RCE）

> 在Springboot中，支持的模板引擎：
>
> * Thymeleaf
> * FreeMarker
> * Velocity
> * JSP
> * Groovy
> * Mustache
> * Handlebars
> * Pebble
>
> Spring Boot 支持多种模板引擎，其中大多数模板引擎都存在 **SSTI（服务器端模板注入）** 风险，具体如下：
>
> 1. **高风险**：Thymeleaf, FreeMarker, Velocity, JSP, Groovy（因为支持复杂的表达式和代码执行）
> 2. **中风险**：Pebble（表达式简单，但仍需小心）
> 3. **低风险**：Mustache, Handlebars（逻辑少、功能有限，SSTI风险较低）



**以Thymeleaf为例**

**模板文件参数可控示例：**

poc:`__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('calc').getInputStream()).next()}__::.x`

```java
 @GetMapping("/thymeleaf/vul")
 public String thymeleafVul(@RequestParam String lang) {
     // 模版文件参数可控
     return "lang/" + lang;
 }
```



**代码分析**

1. `public String thymeleafVul(@RequestParam String lang)`:
   * 该方法接收一个`lang`值，是用户可控的
   * 返回值是`String`，在`Thymeleaf`模板中，会去寻找对应的视图文件
2. `return "lang/" + lang;`
   * 直接将用户可控的lang值拼接到视图名称中，这会导致在进行目标渲染的过程中，执行用户插入的恶意内容



**url作为视图示例**

poc：`__${T(java.lang.Runtime).getRuntime().exec("calc")}__::.x`

```java
 @GetMapping("/doc/{document}")
 public void getDocument(@PathVariable String document) {
     System.out.println(document);
 }
```



**代码分析**

如果controller无返回值，则以GetMapping的路由为视图名称，即将请求的url作为视图名称，调用模板引擎去解析

在这种情况下，只要可以控制请求的controller的参数，一样可以造成RCE漏洞





