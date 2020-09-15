# SpringBoot整合Shiro框架笔记

## SpringBoot整合Shiro环境搭建

### 环境搭建步骤

1. 新建一个SpringBoot项目框架

2. 导入thymeleaf依赖

   ```java
   <dependency>
   	<groupId>org.thymeleaf</groupId>
   	<artifactId>thymeleaf-spring5</artifactId>
   </dependency>
   <dependency>
   	<groupId>org.thymeleaf.extras</groupId>
   	<artifactId>thymeleaf-extras-java8time</artifactId>
   </dependency>
   ```

   thymeleaf的命名空间

   ```html
   xmlns:th="http://www.thymeleaf.org"
   ```

3. 编写一个index页面和controller测试thymeleaf环境是否正常

4. 导入shiro整合spring的依赖

   ```xml
   <dependency>
               <groupId>org.apache.shiro</groupId>
               <artifactId>shiro-spring</artifactId>
               <version>1.6.0</version>
   </dependency>
   ```

5. 编写shiro的配置类  自定义Realm --> DefaultWebSecurityManager --> ShiroFilterFactoryBean

   自定义的Realm类，**继承 AuthorizingRealm 类 ** 并实现其中的 授权 和 认证 方法

   ```java
   package com.shiro.shirospringboot.shiroConfig;
   
   import org.apache.shiro.authc.AuthenticationException;
   import org.apache.shiro.authc.AuthenticationInfo;
   import org.apache.shiro.authc.AuthenticationToken;
   import org.apache.shiro.authz.AuthorizationInfo;
   import org.apache.shiro.realm.AuthenticatingRealm;
   import org.apache.shiro.realm.AuthorizingRealm;
   import org.apache.shiro.subject.PrincipalCollection;
   
   public class UserRealm extends AuthorizingRealm {
   
       //授权
       @Override
       protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
           return null;
       }
   
       //认证
       @Override
       protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
           return null;
       }
   }
   
   ```

   shiro的配置类：

   ```java
   package com.shiro.shirospringboot.shiroConfig;
   
   import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
   import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
   import org.springframework.beans.factory.annotation.Qualifier;
   import org.springframework.context.annotation.Bean;
   import org.springframework.context.annotation.Configuration;
   
   @Configuration
   public class shiroConfig {
   
       //ShiroFilterFactoryBean  3
       @Bean
       public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
           ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
           bean.setSecurityManager(defaultWebSecurityManager);
           return bean;
       }
   
       //DefaultWebSecurityManager  2
       @Bean(name = "securityManager")
       public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm){
           DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
           securityManager.setRealm(userRealm);
           return securityManager;
       }
   
       //自定义realm  1
       @Bean
       public UserRealm userRealm(){
           return new UserRealm();
       }
   
   }
   
   ```

6. 写一个add.html 和 update.html，并在controller类中添加相应的响应方法



## Shiro实现登录拦截

ShiroFilterFactoryBean#setFilterChainDefinitionMap() 方法可以设置对不同请求页面的访问权限。 方法的参数是一个Map对象。

anon：无需认证

authc：必须认证才能访问

user：必须拥有 记住我 功能才能访问

perms：拥有对某个资源的权限才能访问

role：拥有某个角色才能访问

如果登录失败，不会自动跳转到框架内置的登录页面（Shiro没有），需要通过 setLoginUrl() 方法来设置登录页面(实际上是触发了一次请求，因此需要在controller中编写相应的方法处理该请求，然后跳转到登录页面)。

```java
//ShiroFilterFactoryBean  3
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        Map<String, String> filterMap = new LinkedHashMap<>();
        filterMap.put("/user/add", "authc");
        filterMap.put("/user/update", "authc");
        bean.setFilterChainDefinitionMap(filterMap);
        bean.setLoginUrl("/toLogin");
        bean.setSecurityManager(defaultWebSecurityManager);
        return bean;
    }
```

```java
//controller中处理 因未登录导致的跳转失败 而出发的请求
@RequestMapping("/toLogin")
    public String toLogin(){
        return "/user/login";
    }
```



## Shiro实现用户认证

### 用户认证步骤

1. 在登陆页面，填写完表单信息，点击提交后，发送"/login"请求

   ```html
   <form th:action="@{/login}">
           <p>用户名: <input name="username" type="text"></p>
           <p>密码: <input name="password" type="password"></p>
           <p><input type="submit"></p>
   </form>
   ```

2. 在MyController类中，有响应"/login"请求的方法。在该方法中首先获取subject对象，然后将前端页面发送过来的username、password封装成UsernamePasswordToken对象，然后执行Subject#login(token) 方法。

   ```java
   @RequestMapping("/login")
   public String login(String username, String password, Model model){
       Subject subject = SecurityUtils.getSubject();
       UsernamePasswordToken token = new UsernamePasswordToken(username, password);
       try {
           subject.login(token);  //该login() 方法 是通过自定义Realm重写的认证方法来完成的
           return "index";
       }catch (UnknownAccountException e){
           model.addAttribute("msg", "用户不存在");
           return "/user/login";
       }catch (IncorrectCredentialsException e){
           model.addAttribute("msg", "密码错误");
           return "/user/login";
       }
   }
   ```

3. Subject#login() 方法，实际上使用到了自定义Realm中的认证方法。在该认证方法中

   ```java
   //认证
       @Override
       protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
           String username = "root";
           String password = "123456";
   
           UsernamePasswordToken userToken = (UsernamePasswordToken) authenticationToken;
   
           if(!userToken.getUsername().equals(username)){  //对用户名进行认证
               System.out.println("进行用户名认证");
               return null;  //返回null，则是 UnknownAccountException 异常
           }
           //对密码进行认证，shiro不允许getPassword来进行比较，以防密码泄露问题。而是通过下面这个方法来进行密码的校验
           return new SimpleAuthenticationInfo("", password, ""); 
       }
   ```

### 用户认证原理

1. 自己写的controller类中处理登录请求方法中的 Subject#login() 方法，进入

2. DelegatingSubject 类 login() 方法， 重新定义了一个subject对象， 通过 securityManager#login() 方法获得，进入该方法。![image-20200915111022455](D:\markdown的笔记\Typora\images\image-20200915111022455.png)

3. 该类的 login() 方法中定义了一个 AuthenticationInfo 对象，通过 authenticate() 方法获得，进入。

   ![image-20200915111214022](D:\markdown的笔记\Typora\images\image-20200915111214022.png)

4. 通过层级的调用，都是为了获取 AuthenticationInfo 

   ![image-20200915111453630](D:\markdown的笔记\Typora\images\image-20200915111453630.png)

   ![image-20200915111535528](D:\markdown的笔记\Typora\images\image-20200915111535528.png)

5. 在doAuthenticate() 方法中，获取所有的Realm。因为自己只写了一个realm，所以会执行 doSingleRealmAuthentication() 方法。进入该方法

   ![image-20200915111745465](D:\markdown的笔记\Typora\images\image-20200915111745465.png)

6. 该方法首先判断realm是否支持token。然后通过getAuthenticationInfo() 方法来获取 AuthenticationInfo 对象。进入该方法

   ![image-20200915111839999](D:\markdown的笔记\Typora\images\image-20200915111839999.png)

7. 首先判断缓存中是否有，如果第一次登录即没有。然后调用doGetAuthenticationInfo() 方法。点进这个方法，发现实际上调用的是自己写的realm中重写的doGetAuthenticationInfo() 方法来进行用户认证。

   ![image-20200915112617203](D:\markdown的笔记\Typora\images\image-20200915112617203.png)

   ![image-20200915112105471](D:\markdown的笔记\Typora\images\image-20200915112105471.png)

8. 进行密码校验

   ![image-20200915113420028](D:\markdown的笔记\Typora\images\image-20200915113420028.png)

   ![image-20200915113443847](D:\markdown的笔记\Typora\images\image-20200915113443847.png)

   

## Shiro整合Mybatis

1. 添加mysql、mybatis、log4j、druid、lombok依赖

   ```xml
   <dependency>
       <groupId>mysql</groupId>
       <artifactId>mysql-connector-java</artifactId>
       <version>8.0.21</version>
   </dependency>
   <dependency>
       <groupId>org.mybatis.spring.boot</groupId>
       <artifactId>mybatis-spring-boot-starter</artifactId>
       <version>2.1.1</version>
   </dependency>
   <dependency>
       <groupId>log4j</groupId>
       <artifactId>log4j</artifactId>
       <version>1.2.17</version>
   </dependency>
   <dependency>
       <groupId>com.alibaba</groupId>
       <artifactId>druid</artifactId>
       <version>1.1.23</version>
   </dependency>
   <dependency>
       <groupId>org.projectlombok</groupId>
       <artifactId>lombok</artifactId>
       <version>1.18.12</version>
       <scope>provided</scope>
   </dependency>
   
   ```

2. 写数据源的配置

   ```yml
   spring:
     datasource:
       username: root
       password: root
       #?serverTimezone=UTC解决时区的报错
       url: jdbc:mysql://localhost:3306/mybatis?serverTimezone=UTC
       driver-class-name: com.mysql.cj.jdbc.Driver
       type: com.alibaba.druid.pool.DruidDataSource
   
       #Spring Boot 默认是不注入这些属性值的，需要自己绑定
       #druid 数据源专有配置
       initialSize: 5
       minIdle: 5
       maxActive: 20
       maxWait: 60000
       timeBetweenEvictionRunsMillis: 60000
       minEvictableIdleTimeMillis: 300000
       validationQuery: SELECT 1 FROM DUAL
       testWhileIdle: true
       testOnBorrow: false
       testOnReturn: false
       poolPreparedStatements: true
   
       #配置监控统计拦截的filters，stat:监控统计、log4j：日志记录、wall：防御sql注入
       #如果允许时报错  java.lang.ClassNotFoundException: org.apache.log4j.Priority
       #则导入 log4j 依赖即可，Maven 地址：https://mvnrepository.com/artifact/log4j/log4j
       filters: stat,wall,log4j
       maxPoolPreparedStatementPerConnectionSize: 20
       useGlobalDataSourceStat: true
       connectionProperties: druid.stat.mergeSql=true;druid.stat.slowSqlMillis=500
   ```

3. 写mybatis的配置

   ```properties
   mybatis.type-aliases-package=com.shiro.shirospringboot.pojo
   mybatis.mapper-locations=classpath:mapper/*.xml
   ```

4. 编写pojo类

   ```java
   package com.shiro.shirospringboot.pojo;
   
   import lombok.AllArgsConstructor;
   import lombok.Data;
   import lombok.NoArgsConstructor;
   
   @Data  //lombok的注解
   @AllArgsConstructor  //lombok的注解
   @NoArgsConstructor   //lombok的注解
   public class User {
       private int id;
       private String name;
       private String pwd;
   }
   
   ```

5. 写mapper接口和mapper文件

   ```java
   package com.shiro.shirospringboot.mapper;
   
   import com.shiro.shirospringboot.pojo.User;
   import org.apache.ibatis.annotations.Mapper;
   import org.springframework.stereotype.Repository;
   
   @Repository
   @Mapper
   public interface UserMapper {
   
       public User getUserByName(String name);
   
   }
   ```

   ```xml
   <?xml version="1.0" encoding="utf-8" ?>
   <!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd" >
   <mapper namespace="com.shiro.shirospringboot.mapper.UserMapper">
   
       <select id="getUserByName" parameterType="string" resultType="com.shiro.shirospringboot.pojo.User">
           select * from user where name = #{name}
       </select>
   
   </mapper>
   ```

6. 写service层

   ```java
   package com.shiro.shirospringboot.service;
   
   import com.shiro.shirospringboot.pojo.User;
   
   public interface UserService {
   
       public User getUserByName(String name);
   
   }
   ```

   ```java
   package com.shiro.shirospringboot.service;
   
   import com.shiro.shirospringboot.mapper.UserMapper;
   import com.shiro.shirospringboot.pojo.User;
   import org.springframework.beans.factory.annotation.Autowired;
   import org.springframework.stereotype.Service;
   
   @Service
   public class UserServiceImpl implements UserService {
   
       @Autowired
       UserMapper userMapper;
   
       @Override
       public User getUserByName(String name) {
           return userMapper.getUserByName(name);
       }
   }
   ```

7. 改造Realm类的认证方法

   ```java
   package com.shiro.shirospringboot.shiroConfig;
   
   import com.shiro.shirospringboot.pojo.User;
   import com.shiro.shirospringboot.service.UserService;
   import org.apache.shiro.authc.*;
   import org.apache.shiro.authz.AuthorizationInfo;
   import org.apache.shiro.realm.AuthenticatingRealm;
   import org.apache.shiro.realm.AuthorizingRealm;
   import org.apache.shiro.subject.PrincipalCollection;
   import org.springframework.beans.factory.annotation.Autowired;
   
   public class UserRealm extends AuthorizingRealm {
       @Autowired
       UserService userService;
   
       //授权
       @Override
       protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
           return null;
       }
   
       //认证
       @Override
       protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
   
           UsernamePasswordToken userToken = (UsernamePasswordToken) authenticationToken;
           User user = userService.getUserByName(userToken.getUsername());
           if(user == null){
               return null;
           }
           return new SimpleAuthenticationInfo("", user.getPwd(), "");
       }
   }
   
   ```



## Shiro请求授权实现

1. 首先对表结构和pojo进行修改，添加 权限 数据

2. 依然是在 shiroConfig 类 中通过map对象来添加授权信息。给不同的页面授不同的权。并设置登录未授权页面时进行跳转的页面。

   ```java
   @Bean
       public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
           ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
   
           //设置不同页面的访问权限
           Map<String, String> filterMap = new LinkedHashMap<>();
           filterMap.put("/user/add", "authc");
           filterMap.put("/user/update", "authc");
           //给页面授权
           filterMap.put("/user/add", "perms[user:add]");
           filterMap.put("/user/update", "perms[user:update]");
           bean.setFilterChainDefinitionMap(filterMap);
   
           //设置登录请求
           bean.setLoginUrl("/toLogin");
   
           //设置未授权时的跳转页面
           bean.setUnauthorizedUrl("/unauth");
   
           bean.setSecurityManager(defaultWebSecurityManager);
           return bean;
       }
   ```

3. 修改认证方法 ( new SimpleAuthenticationInfo(user, user.getPwd(), ""); )  principal该为该用户

   ```java
   //认证
       @Override
       protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
   
           UsernamePasswordToken userToken = (UsernamePasswordToken) authenticationToken;
           User user = userService.getUserByName(userToken.getUsername());
           if(user == null){
               return null;
           }
           return new SimpleAuthenticationInfo(user, user.getPwd(), "");
       }
   ```

4. 真正授权的业务处理还是在自定义Realm的授权方法中

   ```java
   //授权
   @Override
   protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
       Subject subject = SecurityUtils.getSubject();
       User currentUser = (User) subject.getPrincipal();
       SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
       info.addStringPermission(currentUser.getPerms());
       return info;
   }
   ```



## Shiro整合Thymeleaf

1. 添加shiro-thymeleaf的依赖

   ```xml
   <dependency>
       <groupId>com.github.theborakompanioni</groupId>
       <artifactId>thymeleaf-extras-shiro</artifactId>
       <version>2.0.0</version>
   </dependency>
   ```

2. 在 shiroConfig 类中配置

   ```java
   @Bean
   public ShiroDialect getShiroDialect(){
   	return new ShiroDialect();
   }
   ```

3. 修改前端页面，命名空间为

   ```html
   xmlns:shiro="https://www.thymeleaf.org/thymeleaf-extras-shiro"
   ```

4. 更改前端页面

   ```html
   <body>
   <h1>首页</h1>
       <p>
           <a href="/toLogin">登录</a>
       </p>
       <p th:text="${msg}"> </p>
   
       <div shiro:hasPermission="user:add">  //有这项权限，该超链接才显示
           <a th:href="@{/user/add}">add</a>
       </div>
       <div shiro:hasPermission="user:update">
           <a th:href="@{/user/update}">update</a>
       </div>
   </body>
   ```

   

## 本次学习用到的博客

https://www.cnblogs.com/Vito-Yan/p/10524645.html

https://www.cnblogs.com/hellokuangshen/p/12497041.html

https://www.cnblogs.com/hellokuangshen/p/12503200.html

https://www.jianshu.com/p/b934b0d72602



## 补充学习的知识

1. ![image-20200915093527842](D:\markdown的笔记\Typora\images\image-20200915093527842.png)

2. @Data：注解在类上, 为类提供读写属性, 此外还重写了 equals()、hashCode()、toString() 方法

3. @Mapper和@Repository

   https://blog.csdn.net/Xu_JL1997/article/details/90934359?depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-1&utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-1


