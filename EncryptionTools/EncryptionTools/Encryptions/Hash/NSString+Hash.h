//
//  NSString+Hash.h
//  Encryptions
//
//  Created by mdd on 15/5/17.
//  Copyright © 2015年 com.personal. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Hash)

/// 返回结果：32长度(128位，16字节，16进制字符输出则为32字节长度)   终端命令：md5 -s "123"
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
@end
