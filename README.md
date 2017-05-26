# EncryptionTools
加密工具： Base64 MD5 SHA1 SHA224 SHA256 SHA384 HMAC(SHA1~SHA512) AES DES RSA

`NSString+Hash.m`与`NSString+Hash.h`文件实现了`MD5 SHA1 SHA224 SHA256 SHA384 HMAC(SHA1~SHA512)`可以单独拷贝出来使用

`NSString+Encryption.m`与`NSString+Encryption.h`文件实现了AES DES RSA加密解密，也可以单独拷贝出来使用

## 更新NSString+Hash
hmacSHA有笔误，错把 `const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];`写为`const char *cKey = [self cStringUsingEncoding:NSUTF8StringEncoding];`，感谢简书 @靓模袭地球

---

---

## 一、Base64编码
Base64编码要求把3个8位字节`（3*8=24）`转化为4个6位的字节`（4*6=24）`，之后在6位的前面补两个0，形成8位一个字节的形式，这样每一个字节的有效位为6位，则取值范围0~63`0 ~ (2^6 - 1)`。如果最后剩下的字符不到3个字节，则用0填充，输出字符使用'='，因此我们看到Base64末尾会有1到2个'='。另外标准还要求每76个字符要插入换行(不过，这个视具体情况定)。

iOS7之后苹果有自己的Base64编码解码API，NSData的扩展：`NSData (NSDataBase64Encoding)`


#### 两种存储方式
* 可见字符串形式

为了保证所输出的每一个编码字节都是可读字符，而不是0~63这些数字，Base64制作了一个码表，就像ASCII码表一样，每一个Base64码值都有对应的字符。64个可读字符从0到63非别是`A-Z、a-z、0-9、+、/`，这也是Base64名字的由来。

* 以16进制形式

即NSData形式保存，Base64编码结果为字符，而这些字符又对应ASCII码表的码值，NSData就是存储ASCII码表的码值。


#### 下面举个例子，并以苹果提供的API来详细介绍Base64编码解码过程：

假设我们对字符串"123"进行Base64编码，"123"对应的16进制是313233，二进制为`00110001、00110010、00110011`，将其变为4*6结果即下表中的第一行。然后根据Base64的码表，它们分别对应表中的第二行。那么"123"编码的最终结果即为MTIz，以字符串的形式保存。然后根据MTIz对应ASCII码值，以NSData形式存储，如表中的第三行。

转换为4*6结果 | 00001100 |   00010011 |  00001000 | 00110011
----|-------- | ---------- | --------- | --------
Base64对应字符|M        |  T         | I         | z
对应ASCII码值(16进制)|4d         |54         | 49        |7a

上面的过程通过代码实现如下：

```
// 1 待编码的原始字符串
NSString *plainStr = @"123";
// 2 将其转换成NSData保存，那么"123"对应的ASCII码表码值是31、32、33（16进制）
NSData *plainData = [plainStr dataUsingEncoding:NSUTF8StringEncoding];
// 3.1 将其进行Base64编码，且结果以字符串形式保存，对应表中的第二行
NSString *baseStr = [plainData base64EncodedStringWithOptions:0];
// 3.2 将其进行Base64编码，且结果以NSData形式保存
NSData *base64Data = [plainData base64EncodedDataWithOptions:0];
```
另外对于参数NSDataBase64EncodingOptions选项，有多种取值

* NSDataBase64Encoding64CharacterLineLength：每64个字符插入\r或\n
* NSDataBase64Encoding76CharacterLineLength：每76个字符插入\r或\n，标准中有要求是76个字符要换行，不过具体还是自己定
* NSDataBase64EncodingEndLineWithCarriageReturn：插入字符为\r
* NSDataBase64EncodingEndLineWithLineFeed：插入字符为\n

前两个选项为是否允许插入字符，以及多少个字符长度插入，两个可以选其一或者都不选。后两个选项代表要插入的具体字符。比如我们想76个字符后插入一个\r则可以`NSDataBase64Encoding76CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn`。而在上面举的例子中选项为0，则代表不插入字符。

####第三方框架
在iOS7之前我们一般用的都是第三方框架，比如nicklockwood写的[https://github.com/nicklockwood/Base64](https://github.com/nicklockwood/Base64)还有Google的GTMBase64，虽然苹果有了自己的实现，但是许多其它的加密框架都用到了它，所以还是要了解一下，另外它还提供任意长度字符插入`\r\n`，而苹果只能是64或76长度。

##二、MD5、SHA1、SHA256、SHA512、HMAC实现
主要用于验证，防止信息被修改。介绍请参照[http://www.jianshu.com/p/003b85fd3e36](http://www.jianshu.com/p/003b85fd3e36)。

具体的实现参考第三方框架：[https://github.com/kelp404/CocoaSecurity](https://github.com/kelp404/CocoaSecurity)。非常全面，不过不是太方便，比如想要获得MD5结果

```
NSString *plainStr = @"123";
CocoaSecurityResult *md5 = [CocoaSecurity md5:plainStr];
// 获取md5结果
NSString *md5Str = md5.hexLower;
```

不能直接plainStr.MD5Hash就获得字符串形式的结果，这里我封装了一个，可以参见工程中的NSString+Hash类[https://github.com/mddios/EncryptionTools](https://github.com/mddios/EncryptionTools),可以直接对字符串进行操作，类似`plainStr.MD5Hash、plainStr.sha1Hash···plainStr.sha256Hash···`，非常方便。

比如对@"123"哈希，下面用上面提到的两种方法举例:

```
- (void)hashTest {
NSString *plainStr = @"123";
// md5
CocoaSecurityResult *md5 = [CocoaSecurity md5:plainStr];
NSLog(@"md5:%lu---%@---%@",plainStr.md5Hash.length, plainStr.md5Hash,md5.hex);
// 40
CocoaSecurityResult *sha1 = [CocoaSecurity sha1:plainStr];
NSLog(@"sha1:%lu---%@---%@",plainStr.sha1Hash.length,  plainStr.sha1Hash,sha1.hex);
// 56
CocoaSecurityResult *sha224 = [CocoaSecurity sha224:plainStr];
NSLog(@"sha224:%lu---%@---%@",plainStr.sha224Hash.length,plainStr.sha224Hash,sha224.hex);
// 64
CocoaSecurityResult *sha256 = [CocoaSecurity sha256:plainStr];
NSLog(@"sha256:%lu---%@---%@",plainStr.sha256Hash.length,plainStr.sha256Hash,sha256.hex);
// 96
CocoaSecurityResult *sha384 = [CocoaSecurity sha384:plainStr];
NSLog(@"sha384:%lu---%@---%@",plainStr.sha384Hash.length,plainStr.sha384Hash,sha384.hex);
// 128
CocoaSecurityResult *sha512 = [CocoaSecurity sha512:plainStr];
NSLog(@"sha512:%lu---%@---%@",plainStr.sha512Hash.length,plainStr.sha512Hash,sha512.hex);

// hmac
CocoaSecurityResult *hmacmd5 = [CocoaSecurity hmacMd5:plainStr hmacKey:plainStr];
NSLog(@"hmacmd5:%lu---%@---%@",[plainStr hmacMD5WithKey:plainStr].length,[plainStr hmacMD5WithKey:plainStr],hmacmd5.hex);
}
```

* 在电脑终端来获取结果

封装的代码中`NSString+Hash.h`头文件，有具体列出终端命令方法，如下：

```
/// 返回结果：32长度   终端命令：md5 -s "123"
- (NSString *)md5Hash;

/// 返回结果：40长度   终端命令：echo -n "123" | openssl sha -sha1
- (NSString *)sha1Hash;

/// 返回结果：56长度   终端命令：echo -n "123" | openssl sha -sha224
- (NSString *)sha224Hash;

/// 返回结果：64长度   终端命令：echo -n "123" | openssl sha -sha256
- (NSString *)sha256Hash;

/// 返回结果：96长度   终端命令：echo -n "123" | openssl sha -sha384
- (NSString *)sha384Hash;

/// 返回结果：128长度   终端命令：echo -n "123" | openssl sha -sha512
- (NSString *)sha512Hash;

#pragma mark - HMAC

/// 返回结果：32长度  终端命令：echo -n "123" | openssl dgst -md5 -hmac "123"
- (NSString *)hmacMD5WithKey:(NSString *)key;

/// 返回结果：40长度   echo -n "123" | openssl sha -sha1 -hmac "123"
- (NSString *)hmacSHA1WithKey:(NSString *)key;
- (NSString *)hmacSHA224WithKey:(NSString *)key;
- (NSString *)hmacSHA256WithKey:(NSString *)key;
- (NSString *)hmacSHA384WithKey:(NSString *)key;
- (NSString *)hmacSHA512WithKey:(NSString *)key;
```


* 关于MD5加盐，只是多了下面第一行

```
plainStr = [plainStr stringByAppendingString:salt];
NSString *md5Str = plainStr.md5Hash;
```

博客：

* [http://www.jianshu.com/p/185a581e7afa](http://www.jianshu.com/p/185a581e7afa)
* [http://www.cnblogs.com/mddblog/p/5512708.html](http://www.cnblogs.com/mddblog/p/5512708.html)
