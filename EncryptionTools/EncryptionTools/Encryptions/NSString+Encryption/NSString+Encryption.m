//
//  NSString+Encryption.m
//  EncryptionTools
//
//  Created by mdd on 16/4/2.
//  Copyright © 2016年 com.personal. All rights reserved.
//

#import "NSString+Encryption.h"
#import "NSString+Hash.h"

@implementation NSString (Encryption)

#pragma mark - AES加密

/*
 默认CBC模式，返回base64编码
 */
- (NSString *)aesEncryptWithHexKey:(NSString *)key hexIv:(NSString *)iv {
    NSData *aesKey = [key dataFromHexString];
    if (iv == nil) {
        // 32长度
        iv = @"00000000000000000000000000000000";
    }
    NSData *aesIv = [iv dataFromHexString];
    NSData *resultData = [self aesEncryptWithDataKey:aesKey dataIv:aesIv];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 默认CBC模式，返回base64编码
 */
- (NSString *)aesEncryptWithKey:(NSString *)key iv:(NSString *)iv {
    NSData *aesKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    if (iv == nil) {
        // 32长度
        iv = @"00000000000000000000000000000000";
    }
    NSData *aesIv = [iv dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self aesEncryptWithDataKey:aesKey dataIv:aesIv];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 CBC模式，返回NSData
 */
- (NSData *)aesEncryptWithDataKey:(NSData *)key dataIv:(NSData *)iv {
    return [self aesEncryptOrDecrypt:kCCEncrypt data:[self dataUsingEncoding:NSUTF8StringEncoding] dataKey:key dataIv:iv mode:kPaddingMode];
}

/*
 ECB模式，返回base64编码
 */
- (NSString *)aesECBEncryptWithHexKey:(NSString *)key {
    NSData *aesKey = [key dataFromHexString];
    NSData *resultData = [self aesECBEncryptWithDataKey:aesKey];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 ECB模式，返回base64编码
 */
- (NSString *)aesECBEncryptWithKey:(NSString *)key {
    NSData *aesKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self aesECBEncryptWithDataKey:aesKey];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 ECB模式，返回base64
 */
- (NSString *)aesECBEncryptWithBase64Key:(NSString *)key {
    NSData *aesKey = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *resultData = [self aesECBEncryptWithDataKey:aesKey];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 ECB模式，返回NSData
 */
- (NSData *)aesECBEncryptWithDataKey:(NSData *)key {
    NSData *aesIv = [@"00000000000000000000000000000000" dataFromHexString];
    return [self aesEncryptOrDecrypt:kCCEncrypt data:[self dataUsingEncoding:NSUTF8StringEncoding] dataKey:key dataIv:aesIv mode:kPaddingMode | kCCOptionECBMode];
}

#pragma mark - AES解密

/*
 默认CBC模式解密，默认string为base64格式
 */
- (NSString *)aesBase64StringDecryptWithHexKey:(NSString *)key hexIv:(NSString *)iv {
    NSData *aesKey = [key dataFromHexString];
    if (iv == nil) {
        // 32长度
        iv = @"00000000000000000000000000000000";
    }
    NSData *aesIv = [iv dataFromHexString];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    NSData *resultData = [NSString aesDecryptWithData:data dataKey:aesKey dataIv:aesIv];
    return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
}

/*
 CBC模式解密，返回NSData
 */
+ (NSData *)aesDecryptWithData:(NSData *)data dataKey:(NSData *)key dataIv:(NSData *)iv {
    return [[NSString alloc] aesEncryptOrDecrypt:kCCDecrypt data:data dataKey:key dataIv:iv mode:kPaddingMode];
}

/*
 ECB模式解密，要求输入为Base64格式，返回为NSString
 */
- (NSString *)aesECBBase64StringDecryptWithHexKey:(NSString *)key {
    NSData *aesKey = [key dataFromHexString];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    NSData *resultData = [NSString aesECBDecryptWithData:data withDataKey:aesKey];
    return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
}

/*
 ECB模式解密，要求输入为Base64格式，返回为NSString
 */
- (NSString *)aesECBBase64StringDecryptWithBase64Key:(NSString *)key {
    NSData *aesKey = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    NSData *resultData = [NSString aesECBDecryptWithData:data withDataKey:aesKey];
    return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
}

/*
 ECB模式解密，返回为NSData
 */
+ (NSData *)aesECBDecryptWithData:(NSData *)data withDataKey:(NSData *)key{
    NSData *aesIv = [@"00000000000000000000000000000000" dataFromHexString];
    return [[NSString alloc] aesEncryptOrDecrypt:kCCDecrypt data:data dataKey:key dataIv:aesIv mode:kPaddingMode | kCCOptionECBMode];
}

///*
// ECB模式解密，返回base64编码
// */
//- (NSString *)aesECBDecryptWithHexKey:(NSString *)key {
//    NSData *aesKey = [key dataFromHexString];
//    NSData *resultData = [self aesECBEncryptWithDataKey:aesKey];
//    return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];;
//}
//
///*
// ECB模式解密，返回NSData
// */
//- (NSData *)aesECBDecryptWithDataKey:(NSData *)key {
//    NSData *aesIv = [@"00000000000000000000000000000000" dataFromHexString];
//    return [self aesEncryptOrDecrypt:kCCDecrypt data:[self dataUsingEncoding:NSUTF8StringEncoding] dataKey:key dataIv:aesIv mode:kPaddingMode | kCCOptionECBMode];
//}


- (NSData *)aesEncryptOrDecrypt:(CCOperation)option data:(NSData *)data dataKey:(NSData *)key dataIv:(NSData *)iv mode:(int)mode{
    // check length of key and iv
    if ([iv length] != 16) {
        @throw [NSException exceptionWithName:@"Encrypt"
                                       reason:@"Length of iv is wrong. Length of iv should be 16(128bits)"
                                     userInfo:nil];
    }
    if ([key length] != 16 && [key length] != 24 && [key length] != 32 ) {
        @throw [NSException exceptionWithName:@"Encrypt"
                                       reason:@"Length of key is wrong. Length of iv should be 16, 24 or 32(128, 192 or 256bits)"
                                     userInfo:nil];
    }
    
    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(option,
                                          kCCAlgorithmAES128,
                                          mode,
                                          [key bytes],     // Key
                                          [key length],    // kCCKeySizeAES
                                          [iv bytes],      // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    NSData *resultData = nil;
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytes:buffer length:encryptedSize];        
        free(buffer);
        return resultData;
    } else {
        free(buffer);
        @throw [NSException exceptionWithName:@"Encrypt"
                                       reason:@"Encrypt Error!"
                                     userInfo:nil];
        return resultData;
    }
    return resultData;
}

#pragma mark - DES加密

/*
 DES加密 key为NSString形式 结果返回base64编码
 */
- (NSString *)desEncryptWithKey:(NSString *)key {
    NSData *desKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *resultData = [self desEncryptWithDataKey:desKey];
    return [resultData base64EncodedStringWithOptions:0];
}

/*
 DES加密 key为NSData形式 结果返回NSData
 */
- (NSData *)desEncryptWithDataKey:(NSData *)key {
    return [self desEncryptOrDecrypt:kCCEncrypt data:[self dataUsingEncoding:NSUTF8StringEncoding] dataKey:key mode:kPaddingMode | kCCOptionECBMode];
}

#pragma mark - DES解密

- (NSString *)desDecryptWithKey:(NSString *)key {
    NSData *desKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    NSData *resultData = [NSString desDecryptWithData:data dataKey:desKey];
    return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
}

+ (NSData *)desDecryptWithData:(NSData *)data dataKey:(NSData *)key {
    return [[NSString alloc] desEncryptOrDecrypt:kCCDecrypt data:data dataKey:key mode:kPaddingMode | kCCOptionECBMode];
}

- (NSData *)desEncryptOrDecrypt:(CCOperation)option data:(NSData *)data dataKey:(NSData *)key mode:(int)mode{
//    if ([key length] != 16 && [key length] != 24 && [key length] != 32 ) {
//        @throw [NSException exceptionWithName:@"Encrypt"
//                                       reason:@"Length of key is wrong. Length of iv should be 16, 24 or 32(128, 192 or 256bits)"
//                                     userInfo:nil];
//    }
    
    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeDES;
    void *buffer = malloc(bufferSize);
    
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(option,
                                          kCCAlgorithmDES,
                                          mode,
                                          [key bytes],     // Key
                                          kCCKeySizeDES,    // kCCKeySizeAES
                                          NULL,            // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    NSData *resultData = nil;
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytes:buffer length:encryptedSize];
        free(buffer);
        return resultData;
    } else {
        free(buffer);
        @throw [NSException exceptionWithName:@"Encrypt"
                                       reason:@"Encrypt Error!"
                                     userInfo:nil];
        return resultData;
    }
    return resultData;
}

/**
 hex形式的字符串转换为data
 */
- (NSData *)dataFromHexString {
    
    if (self.length == 0) {
        return nil;
    }
    
    static const unsigned char HexDecodeChars[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, //49
        2, 3, 4, 5, 6, 7, 8, 9, 0, 0, //59
        0, 0, 0, 0, 0, 10, 11, 12, 13, 14,
        15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  //79
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 10, 11, 12,   //99
        13, 14, 15
    };
    
    // convert data(NSString) to CString
    const char *source = [self cStringUsingEncoding:NSUTF8StringEncoding];
    // malloc buffer
    unsigned char *buffer;
    NSUInteger length = strlen(source) / 2;
    buffer = malloc(length);
    for (NSUInteger index = 0; index < length; index++) {
        buffer[index] = (HexDecodeChars[source[index * 2]] << 4) + (HexDecodeChars[source[index * 2 + 1]]);
    }
    // init result NSData
    NSData *result = [NSData dataWithBytes:buffer length:length];
    free(buffer);
    source = nil;
    
    return  result;
}

@end


