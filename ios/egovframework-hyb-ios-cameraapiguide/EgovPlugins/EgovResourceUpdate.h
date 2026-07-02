//
//  EgovResUpdate.h
//  DEVICEAPI
//
//  Created by shin yongho on 2016. 6. 24..
//
//
#import <Cordova/CDVPlugin.h>
#import "EgovZip.h"
#import "EGovComModule.h"

@interface EgovResourceUpdate : CDVPlugin
+ (NSString*)getBundleID;

- (void)update:(CDVInvokedUrlCommand *)command;

- (void)getAppId:(CDVInvokedUrlCommand *)command;
- (void)getAppVersion:(CDVInvokedUrlCommand *)command;
- (void)getResourceVersion:(CDVInvokedUrlCommand *)command;

@property (nonatomic, retain) NSString* callbackID;
@property (nonatomic, retain) NSMutableData *receivedData;
@property (nonatomic, retain) NSString *resVersion;
@property (nonatomic, retain) NSString *fileDownloadLocalPath;
@property (nonatomic, retain) NSString *fileUnzipPath;
@property (nonatomic, retain) NSString *resLastestVersion;
@property (nonatomic, retain) NSString *resVersionUpdDt;
@property (nonatomic, retain) NSString *expectedSha256;

@property (nonatomic, retain) UIProgressView *progressView;
@property (nonatomic, retain) UIAlertView *progressAlert;
@property (nonatomic, retain) UIView *dialogView;
@property (nonatomic, retain) UILabel *labelMessage;

@property (nonatomic) long expectedContentLength;
@property (nonatomic) long downloadContentLength;



@end
