//
//  ViewController.m
//  EncryptionTools
//
//  Created by mdd on 16/5/17.
//  Copyright © 2016年 com.personal. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Hash.h"
#import "CocoaSecurity.h"
#import "NSString+Encryption.h"
#import "RSA.h"

@interface ViewController ()
@property (nonatomic, strong) NSData *data;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self base64Test];
    
    [self hashTest];
    
    [self aesCBCTest];
    [self aesECBTest];
    [self desTest];
    
    [self rsaTest];
}

- (void)base64Test {
    // 1 待编码的原始字符串
    NSString *plainStr = @"123";
    // 2 将其转换成NSData保存，那么"123"对应的ASCII码表码值是31、32、33（16进制）
    NSData *plainData = [plainStr dataUsingEncoding:NSUTF8StringEncoding];
    // 3.1 将其进行Base64编码，且结果以字符串形式保存
    NSString *baseStr = [plainData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    // 3.2 将其进行Base64编码，且结果以NSData形式保存
    NSData *base64Data = [plainData base64EncodedDataWithOptions:0];
    
    NSLog(@"%@---%@---%@---%@", plainData,base64Data,[NSString stringWithUTF8String:[base64Data bytes]],baseStr);
}

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
    
    /// hmac
    CocoaSecurityResult *hmacmd5 = [CocoaSecurity hmacMd5:plainStr hmacKey:plainStr];
    NSLog(@"hmacmd5:%lu---%@---%@",[plainStr hmacMD5WithKey:plainStr].length,[plainStr hmacMD5WithKey:plainStr],hmacmd5.hex);
}

- (void)aesCBCTest {
    NSString *plainText = @"123";
    
    NSString *key128 = @"0123456789ABCDEF";
    // 16进制字符串
    NSString *key128Hex = @"30313233343536373839414243444546";
    
    NSString *iv = @"0123456789ABCDEF";
    // 16进制字符串
    NSString *ivHex = @"30313233343536373839414243444546";
    
    CocoaSecurityResult *result = [CocoaSecurity aesEncrypt:plainText hexKey:key128Hex hexIv:ivHex];
    
    NSString *aesBase64 = [plainText aesEncryptWithKey:key128 iv:iv];
    NSData *aesData = [plainText aesEncryptWithDataKey:[key128 dataUsingEncoding:NSUTF8StringEncoding] dataIv:[iv dataUsingEncoding:NSUTF8StringEncoding]];
    NSLog(@"SecurityResult加密：\r\n%@ --- %@",result.base64,result.hexLower);
    NSLog(@"NSString+Encryption加密：\r\n%@ --- %@",aesBase64,aesData);
    
    // 解密
    NSString *decryptStr = [aesBase64 aesBase64StringDecryptWithHexKey:key128Hex hexIv:ivHex];
    NSData *data = [NSString aesDecryptWithData:aesData dataKey:[key128 dataUsingEncoding:NSUTF8StringEncoding] dataIv:[iv dataUsingEncoding:NSUTF8StringEncoding]];
    NSLog(@"解密：%@ --- %@",decryptStr,data);
}

- (void)aesECBTest {
    NSString *plainText = @"123";
    
    NSString *key128 = @"0123456789ABCDEF";
    
    NSString *aesBase64 = [plainText aesECBEncryptWithKey:key128];
    NSData *aesData = [plainText aesECBEncryptWithDataKey:[key128 dataUsingEncoding:NSUTF8StringEncoding]];
    NSLog(@"加密：%@ --- %@",aesBase64, aesData);
}

- (void)desTest {
    NSString *plainText = @"123";
    
    NSString *key = @"01234567";
    NSString *desBase64 = [plainText desEncryptWithKey:key];
    NSData *keydata = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *desData = [plainText desEncryptWithDataKey:keydata];
    
    NSLog(@"DES加密：%@ --- %@",desBase64,desData);
    
    NSString *decryptStr = [desBase64 desDecryptWithKey:key];
    NSData *data = [NSString desDecryptWithData:desData dataKey:keydata];
    NSLog(@"解密：%@  ---  %@",decryptStr,data);
}

- (void)rsaTest {
    NSString *plainText = @"123";
    NSString *privateKey = @"\
    -----BEGIN PRIVATE KEY-----\
    MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM7GhkiwVsUx5HQ5\
    adz+wXkDcaPQFaygKVBbcEqC8xDzlldUIzruDpci2XmxJbYTIxoh5Dy1GwzQcjig\
    K+U4yNJWB3JmaptR9pkOgNg9bakNsuowOv+jV4rFimyxsDIfpkPIl5M4S73IXtdS\
    wiKWiTNzQP2L649zzKn+8thM8MkRAgMBAAECgYAVQx69zLwvbND0Do9PNTcJzYva\
    72O7K4D0DWL/lnWOEa4s7q7suVvwuJmqRMf+7/rVDhUdFPZiG/ES142L9YnYv7XB\
    NlhZsT80gcGWzh1MO3hqIwZQbbLq4FwU+YH3uyNPeh9w4dVm4VzzSS3KFW6/Hmiw\
    HyhtkduOf7eGf+kgXQJBAPHVuiWW7ddcvTxgmtLWakHcX/zsddzENrR1ZSioFFQI\
    +OoL7xK7Fp108rpEW+RvVTJYk3NDkxvc5m3rn+yKl0MCQQDa4xZ/S6RNGHGIRiFk\
    gkNJoRFh5pYVT6ZzqYLb/9Ny/LuGV0F7XmftRA0paXsNsjdns2a4o9r6tarABKq0\
    EAcbAkA5q/uJbVXpDx+931fswd9zN2fYvFdbP5vAK2LlcDfw1nbt8cygzecVw8cC\
    7rxvXLGXoRIA4fOaKHL3ccKguWhbAkBGh1ePatMlGFQ0wcwus5500hZkwkTn1wNe\
    T2df9f2vFmpiLilmVBQOqpfHGTrSPfOGUZMuuXVsxS6gsqBCZsuzAkAh+/VXDXxh\
    wR7FY8GSfmIq5+7QWjv5nvvqUMtg/WQ3JBl6iGh8ABZg1C8dnhZOmIjGLYVn3EhG\
    74zuyawizSHa\
    -----END PRIVATE KEY-----\
    ";
    
    NSString *publicKey = @"\
    -----BEGIN PUBLIC KEY-----\
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOxoZIsFbFMeR0OWnc/sF5A3Gj\
    0BWsoClQW3BKgvMQ85ZXVCM67g6XItl5sSW2EyMaIeQ8tRsM0HI4oCvlOMjSVgdy\
    ZmqbUfaZDoDYPW2pDbLqMDr/o1eKxYpssbAyH6ZDyJeTOEu9yF7XUsIilokzc0D9\
    i+uPc8yp/vLYTPDJEQIDAQAB\
    -----END PUBLIC KEY-----\
    ";
    
    NSString *encWithPubKey = [RSA encryptString:plainText publicKey:publicKey];
    NSString *decWithPrivKey = [RSA decryptString:encWithPubKey privateKey:privateKey];
    
    NSLog(@"RSA:%@ --- %@",encWithPubKey,decWithPrivKey);
}

@end




