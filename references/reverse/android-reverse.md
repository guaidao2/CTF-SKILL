# Android 逆向 (Android Reverse)

## 原理

分析 Android 应用（APK），反编译 DEX、Native 库，hook 运行时行为，还原算法，找出 flag。

## 攻击链

### 1. APK 结构

```
APK 文件（ZIP 格式）
├── AndroidManifest.xml    # 清单文件（二进制 XML）
├── classes.dex            # Dalvik 字节码
├── classes2.dex           # 多 DEX
├── resources.arsc         # 编译后的资源
├── res/                   # 资源文件
├── assets/                # 原始资源
├── lib/                   # Native 库
│   ├── armeabi-v7a/
│   ├── arm64-v8a/
│   ├── x86/
│   └── x86_64/
├── META-INF/              # 签名
│   ├── MANIFEST.MF
│   ├── CERT.SF
│   └── CERT.RSA
└── kotlin/                # Kotlin 元数据
```

### 2. 反编译

```bash
# apktool
apktool d ./app.apk -o output/
# 反编译资源 + smali

# jadx
jadx ./app.apk -d output/
# 反编译为 Java

# jadx-gui
jadx-gui ./app.apk

# dex2jar + JD-GUI
d2j-dex2jar.sh ./app.apk
jd-gui ./app-dex2jar.jar

# enjarify (Python)
enjarify ./app.apk
```

### 3. Native 库分析

```bash
# 提取 .so 文件
unzip ./app.apk -d apk/
ls apk/lib/arm64-v8a/

# 反编译 .so
ghidra ./libnative.so
ida ./libnative.so
r2 -A ./libnative.so

# JNI 函数
# Java_com_example_app_MainActivity_check
# 命名规则：Java_包名_类名_方法名
```

### 4. 动态分析

#### Frida

```javascript
// hook Java 方法
Java.perform(function() {
    var MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.check.implementation = function(input) {
        console.log('check called with:', input);
        var result = this.check(input);
        console.log('result:', result);
        return result;
    };
});

// hook Native 方法
Interceptor.attach(Module.findExportByName('libnative.so', 'Java_com_example_app_MainActivity_check'), {
    onEnter: function(args) {
        console.log('input:', args[2]);  // JNIEnv, jclass, jstring
    },
    onLeave: function(retval) {
        console.log('return:', retval);
    }
});

// 主动调用
Java.perform(function() {
    var MainActivity = Java.use('com.example.app.MainActivity');
    var instance = MainActivity.$new();
    console.log(instance.check('test'));
});
```

#### Xposed

```java
// Xposed 模块
public class HookModule implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("com.example.app")) return;
        
        XposedHelpers.findAndHookMethod(
            "com.example.app.MainActivity",
            lpparam.classLoader,
            "check",
            String.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("check called with: " + param.args[0]);
                }
                
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("result: " + param.getResult());
                }
            }
        );
    }
}
```

#### 调试

```bash
# gdbserver
adb push gdbserver /data/local/tmp/
adb shell /data/local/tmp/gdbserver :1234 --attach <pid>

# IDA Pro 远程调试
# 1. 启动 android_server
# 2. IDA 连接
```

### 5. 常见保护

#### 加固

```bash
# 常见加固
# - 360 加固
# - 腾讯乐固
# - 阿里聚安全
# - 爱加密
# - 梆梆安全

# 脱壳
# 1. FDex2 (hook ClassLoader)
# 2. DexExtractor
# 3. FRIDA-DEXDump
# 4. BlackDex
# 5. Youpk
```

#### 反调试

```c
// Native 反调试
// 1. ptrace 检测
// 2. /proc/self/status 检测
// 3. 时间检测
// 4. 调试器检测

// Java 反调试
// 1. 检测调试器
// 2. 检测模拟器
// 3. 检测 root
```

#### 签名校验

```java
// 检测签名
PackageManager pm = getPackageManager();
PackageInfo info = pm.getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
Signature[] signatures = info.signatures;
// 比较签名
```

```bash
# 绕过
# 1. 重新签名
# 2. hook 签名校验
# 3. 修改系统
```

### 6. Flutter 逆向

```bash
# Flutter 应用
# 1. 提取 libflutter.so
# 2. 提取 snapshot
# 3. 使用 reFlutter
# 4. 分析 Dart 代码
```

### 7. React Native 逆向

```bash
# React Native 应用
# 1. 提取 JS bundle
# 2. 反混淆 JS
# 3. 分析逻辑
```

## 2024-2026 新技术点

### 1. 新型加固

```python
# 1. VMP 加固
# 2. 抽取加固
# 3. 壳中壳
# 4. 动态加载
# 持续演进
```

### 2. 反 Frida

```python
# 1. 检测 frida-server
# 2. 检测 frida-gadget
# 3. 检测内存中的 Frida
# 4. 检测 Frida 线程
# 5. 检测 Frida 端口
```

### 3. 反模拟器

```python
# 1. 检测模拟器特征
# 2. 检测硬件
# 3. 检测传感器
# 4. 检测行为
```

### 4. 反 root

```python
# 1. 检测 su
# 2. 检测 Magisk
# 3. 检测 root 应用
# 4. 检测 root 行为
```

### 5. Flutter 新版本

```python
# Flutter 3.x
# Dart 3.x
# 新的混淆
# 新的保护
```

### 6. Kotlin/Native

```python
# Kotlin 编译为 Native
# 新的逆向挑战
```

### 7. Jetpack Compose

```python
# 新的 UI 框架
# 新的逆向方法
```

### 8. Android 14+ 新特性

```python
# 新的安全特性
# 新的限制
# 影响逆向
```

### 9. AI 辅助逆向

```python
# LLM 辅助
# - 反编译
# - 算法识别
# - 代码理解
```

### 10. 隐私沙盒

```python
# Android 隐私沙盒
# 新的限制
# 新的逆向方法
```

## 工具推荐

- **apktool** — 反编译资源
- **jadx** — 反编译为 Java
- **Frida** — 动态插桩
- **Xposed** — 模块框架
- **Ghidra** — Native 反编译
- **IDA Pro** — Native 反编译
- **BlackDex** — 脱壳
- **FRIDA-DEXDump** — 脱壳
- **reFlutter** — Flutter 逆向
- **objection** — Frida 封装

## 参考链接

- [ctf-wiki android](https://ctf-wiki.org/android/introduction/)
- [Frida](https://frida.re/)
- [jadx](https://github.com/skylot/jadx)
- [apktool](https://ibotpeaches.github.io/Apktool/)
- [Android Reverse Engineering](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/)
