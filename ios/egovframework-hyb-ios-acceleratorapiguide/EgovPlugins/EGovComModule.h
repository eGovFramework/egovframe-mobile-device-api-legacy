//
//  EGovComModule.h
//  NetworkAPIGuide_iOS
//
//  Created by han chul lee on 12. 6. 29..
//  Copyright (c) 2012년 einslib@naver.com. All rights reserved.
//

//전자정부 모바일 디바이스 API 연동 웹 어플리케이션 접속 URL
//예제) #define kSERVER_URL     @"http://<ipaddress>:<port>/Template-DeviceAPI-Total_Web"
#define kSERVER_URL     @"http://192.168.100.155:9700/Template-DeviceAPI-Total_Web"

// Local: NO / Production: set YES and use https:// in kSERVER_URL
#define kREQUIRE_HTTPS NO

#define kSERVER_OK      200

#import <UIKit/UIKit.h>

@protocol EGovDelegate<NSObject>

@required
@optional
- (void)onNetworkStarted;
- (void)onNetworkFailed:(NSError*)error;
- (void)onNetworkFinished:(NSData*)responseData responseString:(NSString*)responseString responseStatusCode:(NSInteger)responseStatusCode;
@end

@interface EGovComModule : NSObject
{
    
}
- (id)initWithURL:(NSString*)url delegate:(id)delegate;

- (BOOL)setURL:(NSString*)url;
- (BOOL)setTimeOutSeconds:(NSInteger)times;
- (BOOL)addFile:(NSString*)file key:(NSString*)key;
- (BOOL)addPost:(NSString*)post key:(NSString*)key;
- (void)startAsynchronous;

@end
