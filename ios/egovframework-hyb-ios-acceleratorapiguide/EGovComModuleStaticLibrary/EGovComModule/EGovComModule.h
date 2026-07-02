//
//  EGovComModule.h
//  NetworkAPIGuide_iOS
//
//  Created by han chul lee on 12. 6. 29..
//  Copyright (c) 2012년 einslib@naver.com. All rights reserved.
//

#define kSERVER_URL     @"https://192.168.100.86:8080/APIGuide_Web"
#define kSERVER_OK      200

#import <UIKit/UIKit.h>

/**
 EGovComModule Delegate.
 delegate를 연결해야만, 통신 진행 상황을 알 수 있다.
 */
@protocol EGovDelegate<NSObject>
@required
@optional
- (void)onNetworkStarted;
- (void)onNetworkFailed:(NSError*)error;
- (void)onNetworkFinished:(NSData*)responseData responseString:(NSString*)responseString responseStatusCode:(NSInteger)responseStatusCode;
@end

/**
 EGovComModule Class
 */
@interface EGovComModule : NSObject

/**
 초기화 method 반드시 이 method로 초기화 해야된다.
 */
- (id)initWithURL:(NSString*)url delegate:(id)delegate;

/**
 서버 URL을 변경하는 method
 */
- (BOOL)setURL:(NSString*)url;

/**
 서버 통신 시 timeout 시간을 지정한다. 기본 10초.
 */
- (BOOL)setTimeOutSeconds:(NSInteger)times;

/**
 파일을 서버로 전송 method. 파일 경로를 넘겨주면 된다.
 */
- (BOOL)addFile:(NSString*)file key:(NSString*)key;

/**
 특정 값을 서버로 전송 method.
 */
- (BOOL)addPost:(NSString*)post key:(NSString*)key;

/**
 비동기 통신을 시작하는 method
 */
- (void)startAsynchronous;

@end
