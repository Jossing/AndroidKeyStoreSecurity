# AndroidKeyStoreSecurity
利用AndroidKeyStore实现的安全加密方案，适配api18+，可用于保障存储在本地的数据的安全。

## 简介

优点：
1. 密钥运行时随机生成一个，保存在 AndroidKeyStore，泄漏风险低；
2. 密文随机化，降低逆向推导出密钥的可能；

主要的加密方式为 AES256，对于 API21+ 使用 AES/GCM/NoPadding，以下版本则使用 AES/CBC/PKCS7Padding。
加密所使用的偏移量随机，每一次加密都使用强伪随机源产生偏移量，做到密文随机化。

对于 API23+，AndroidKeyStore 可以直接生成和保存 AES 密钥；

对于以下版本，AndroidKeyStore 仅支持 RSA 密钥对，所以这时候就采用 AndroidKeyStore
管理 RSA 密钥对，再使用 RSA 密钥对来管理强伪随机源随机生成的 AES 密钥，经过 RSA 加密的
AES 密钥可以被安全的保存在本地而不用担心泄漏的问题。


# 依赖方式
使用 Gradle 依赖；支持 AndroidX 和 AndroidSupport。
```
repositories {
    jcenter()
}

dependencies {
    implementation 'jossing.android.security:security:1.1.0'
}
```

# 使用
首先在 `Application.onCreate()` 中调用：
```
SecureCryptoConfig.setAppContext(() -> sAppContext);
```
如果你需要加解密相关过程中的 debug log 信息，可以调用以下方法来配置：
```
SecureCryptoConfig.setDebugable(true);
```
##### 普通的加解密使用方式如下：
加密调用 `SecureCrypto.encrypt(byte[])`
```
final byte[] cleartext = data.getBytes();
final byte[] cipherText = SecureCrypto.encrypt(cleartext);
final String encrypted = Base64.encodeToString(cipherText, Base64.NO_WRAP);
```
解密调用 `SecureCrypto.decrypt(byte[])`
```
final byte[] encrypted = Base64.decode(data, Base64.NO_WRAP);
final byte[] cleartext = SecureCrypto.decrypt(encrypted);
final String decrypted = new String(cleartext);
```
##### 如果是针对密钥进行加密或解密，则可以使用以下方式：
加密调用 `SecureCrypto.wrap(Key)`
```
final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
keyGenerator.init(256, SecureRandom.getInstance("SHA1PRNG"));
final SecretKey secretKey = keyGenerator.generateKey();
fianl byte[] wrapped = SecureCrypto.wrap(secretKey);
```
解密调用 `SecureCrypto.unwrap(byte[], String, Class<? extends Key>)`
```
final SecretKey secretKey = SecureCrypto.unwrap(wrapped, "AES", SecretKey.class);
```