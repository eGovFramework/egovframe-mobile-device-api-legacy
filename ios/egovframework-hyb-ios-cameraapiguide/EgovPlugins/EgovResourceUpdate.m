//
//  EgovResUpdate.m
//  DEVICEAPI
//
//  Created by shin yongho on 2016. 6. 24..
//
//

#import "EgovResourceUpdate.h"
#import <CommonCrypto/CommonDigest.h>

static const unsigned long long kMaxUncompressedZipSize = 100ULL * 1024ULL * 1024ULL;

@implementation EgovResourceUpdate

- (void)getAppId:(CDVInvokedUrlCommand *)command {
    
    NSString *appId = [EgovResourceUpdate getBundleID];
    
    NSDictionary *jsonInfo;
    jsonInfo = @{@"appId": appId};
    
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: jsonInfo];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getAppVersion:(CDVInvokedUrlCommand *)command {
    
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    NSString *appVersion = [infoDictionary objectForKey:@"CFBundleShortVersionString"];
    NSString *buildVersion = [infoDictionary objectForKey:@"CFBundleVersion"];
    
    NSDictionary *jsonInfo;
    jsonInfo = @{@"appVersion": appVersion, @"buildVersion": buildVersion};
    
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: jsonInfo];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getResourceVersion:(CDVInvokedUrlCommand *)command {
    
    NSString *resVersion = [EgovResourceUpdate loadFromUserDefaults:@"resVersion"];
    if (resVersion==nil || [resVersion isKindOfClass:[NSNull class]]) {
        resVersion = @"1.0.1";
        self.resVersion = resVersion;
        [EgovResourceUpdate saveToUserDefaults:self.resVersion forKey:@"resVersion"];
        
    }
    
    NSString *resDistDt = [EgovResourceUpdate loadFromUserDefaults:@"resDistDt"];
    NSString *resInstallDt = [EgovResourceUpdate loadFromUserDefaults:@"resInstallDt"];
    
    NSDictionary *jsonInfo;
    jsonInfo = @{@"resVersion": [NSString stringWithFormat:@"%@",resVersion]
                 ,@"resDistDt": [NSString stringWithFormat:@"%@",resDistDt]
                 ,@"resInstallDt": [NSString stringWithFormat:@"%@",resInstallDt]
                 };
    
    
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: jsonInfo];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)update:(CDVInvokedUrlCommand *)command {
    
    NSString *url = [command.arguments objectAtIndex:1];
    NSMutableDictionary *params = [command.arguments objectAtIndex:0];
    self.callbackID = command.callbackId;
    
    NSLog(@"url : %@", url);
    NSLog(@"options : %@", params);
    
    NSString *streFileNm = [params objectForKey:@"streFileNm"];
    NSString *orignlFileNm = [params objectForKey:@"orignlFileNm"];
    NSString *targetPath = [params objectForKey:@"targetPath"];
    
    self.resLastestVersion = [params objectForKey:@"resLastestVersion"];
    self.resVersionUpdDt = [params objectForKey:@"resVersionUpdDt"];
    self.resVersion = [params objectForKey:@"resVersion"];
    self.expectedSha256 = [params objectForKey:@"resFileSha256"];
    
    NSLog(@"streFileNm : %@", streFileNm);
    NSLog(@"orignlFileNm : %@", orignlFileNm);
    NSLog(@"targetPath : %@", targetPath);
    NSLog(@"resLastestVersion : %@", self.resLastestVersion);
    NSLog(@"resVersionUpdDt : %@", self.resVersionUpdDt);
    
    if (self.expectedSha256 == nil || [self.expectedSha256 isKindOfClass:[NSNull class]]
        || [self.expectedSha256 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length == 0) {
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:10 addMessage:@""];
        return;
    }
    self.expectedSha256 = [[self.expectedSha256 lowercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    NSString *downloadAssetFileUrl;
    
    NSArray *pa = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentFilePath = [pa objectAtIndex:0];
    
    NSLog(@">>> documentFilePath %@",documentFilePath);
    
    NSString *safeFileName = [EgovResourceUpdate sanitizeFileName:orignlFileNm];
    NSString *downloadLocalPath = [NSTemporaryDirectory() stringByAppendingPathComponent:safeFileName];
    
    NSError *targetPathError = nil;
    targetPath = [EgovResourceUpdate resolveSecureTargetPath:targetPath documentRoot:documentFilePath error:&targetPathError];
    if (targetPath == nil) {
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:12 addMessage:@""];
        return;
    }
    
    if (url==nil || [url isKindOfClass:[NSNull class]]) {
        NSLog(@"ERROR : url param is null");
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:1 addMessage:@" (URL)"];
        return;
    }
    
    downloadAssetFileUrl = [NSString stringWithFormat:@"%@%@", kSERVER_URL, url];
    NSLog(@"downloadAssetFileUrl : %@", downloadAssetFileUrl);
    
    if (![EgovResourceUpdate isSecureDownloadUrl:downloadAssetFileUrl]) {
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:4 addMessage:@""];
        return;
    }
    
    [self initDialogView:@"리소스 파일을 다운로드 중입니다."];
    [self dialogView:@"show" progress:0];
    
    [self UpdateZipAssetFileAtUrl:downloadAssetFileUrl downloadLocalPath:downloadLocalPath toUnzipPath:targetPath];
    
}


- (BOOL) UpdateZipAssetFileAtUrl:(NSString*)updateFileUrl downloadLocalPath:(NSString*)downloadLocalPath toUnzipPath:(NSString*)unzipPath
{
    self.fileDownloadLocalPath = downloadLocalPath;
    self.fileUnzipPath = unzipPath;
    
    NSLog(@">>> download UPDATEFILE from URL = %@",updateFileUrl);
    NSURLRequest *theRequest=[NSURLRequest requestWithURL:[NSURL URLWithString:updateFileUrl]
                                              cachePolicy:NSURLRequestUseProtocolCachePolicy
                                          timeoutInterval:60.0];
    NSURLConnection *theConnection=[[NSURLConnection alloc] initWithRequest:theRequest delegate:self];
    
    if (theConnection) {
        _receivedData = [NSMutableData data];
    } else {
        NSLog(@"Connection Fail!!!");
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:2 addMessage:@" (URL)"];
        return NO;
    }
    return YES;
    
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    NSLog(@">>> suggestedFilename = %@",response.suggestedFilename);
    NSLog(@">>> expectedContentLength = %lld",response.expectedContentLength);
    if (response.expectedContentLength==0)
        self.expectedContentLength = 1;
    else {
        self.expectedContentLength = response.expectedContentLength;
        self.downloadContentLength = 0;
    }
    [_receivedData setLength:0];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [_receivedData appendData:data];
    self.downloadContentLength += [data length];
    if (self.downloadContentLength > kMaxUncompressedZipSize) {
        [connection cancel];
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:11 addMessage:@""];
        return;
    }
    float progress = (self.downloadContentLength*1.0f)/self.expectedContentLength;
    NSLog(@"progress = %f",progress);
    [self dialogView:@"progress" progress:progress];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"Connection failed! Error - %@ %@",
          [error localizedDescription],
          [[error userInfo] objectForKey:NSURLErrorFailingURLStringErrorKey]);
    
    [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:3 addMessage:[error localizedDescription]];
    
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    NSLog(@"download Finish");
    [_receivedData writeToFile:self.fileDownloadLocalPath atomically:YES];
    
    NSString *actualSha256 = [EgovResourceUpdate computeSha256HexForFileAtPath:self.fileDownloadLocalPath];
    if (actualSha256 == nil || ![self.expectedSha256 isEqualToString:actualSha256]) {
        [[NSFileManager defaultManager] removeItemAtPath:self.fileDownloadLocalPath error:nil];
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:11 addMessage:@""];
        [self dialogView:@"hide" progress:0];
        return;
    }
    
    BOOL ret = [EgovZip doUnZipFileAtPath:self.fileDownloadLocalPath toDestination:self.fileUnzipPath];
    NSLog(@">>> unzip ret %hhd",ret);
    
    [[NSFileManager defaultManager] removeItemAtPath:self.fileDownloadLocalPath error:nil];
    
    if (ret==YES) {
        [EgovResourceUpdate saveToUserDefaults:self.resLastestVersion forKey:@"resVersion"];
        [EgovResourceUpdate saveToUserDefaults:self.resVersionUpdDt forKey:@"resDistDt"];
        
        NSDateFormatter *dateFormatter=[[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
        [EgovResourceUpdate saveToUserDefaults:[dateFormatter stringFromDate:[NSDate date]] forKey:@"resInstallDt"];
        
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:0 addMessage:@""];
        
    } else {
        [self requestCommandDelegateWithCallBackId:self.callbackID errorCode:9 addMessage:@""];
    }
    
    [self dialogView:@"hide" progress:0];
}

- (void) requestCommandDelegateWithCallBackId:(NSString*)callbackID errorCode:(int)errCode addMessage:(NSString*)addMessage {
    NSString *errMessage;
    switch(errCode) {
        case 0:
            errMessage = @"업데이트가 성공적으로 반영되었습니다.";
            break;
        case 1:
            errMessage = @"파라미터에 오류가 있습니다.";
            break;
        case 2:
            errMessage = @"서버연결 실패";
            break;
        case 3:
            errMessage = @"통신오류 : ";
            break;
        case 4:
            errMessage = @"보안 다운로드 URL(HTTPS)만 허용됩니다.";
            break;
        case 9:
            errMessage = @"압축풀기 작업중 오류가 발생했습니다.";
            break;
        case 10:
            errMessage = @"리소스 무결성 검증값(SHA-256)이 필요합니다.";
            break;
        case 11:
            errMessage = @"다운로드한 리소스의 무결성 검증에 실패했습니다.";
            break;
        case 12:
            errMessage = @"허용되지 않은 압축 해제 경로입니다.";
            break;
        default:
            errMessage = @"기타 예외오류가 발생했습니다.";
            break;
    }
    
    NSDictionary *jsonInfo;
    jsonInfo = @{@"resultCode": [NSString stringWithFormat:@"%i",errCode]
                 ,@"resultMsg":[NSString stringWithFormat:@"%@%@",errMessage,addMessage]
                 ,@"resVersion":[NSString stringWithFormat:@"%@",[EgovResourceUpdate loadFromUserDefaults:@"resVersion"]]
                 ,@"resDistDt":[NSString stringWithFormat:@"%@",[EgovResourceUpdate loadFromUserDefaults:@"resDistDt"]]
                 ,@"resInstallDt":[NSString stringWithFormat:@"%@",[EgovResourceUpdate loadFromUserDefaults:@"resInstallDt"]]
                 };
    
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: jsonInfo];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:callbackID];
    
}

+ (NSString*)getBundleID {
    return [[NSBundle mainBundle] bundleIdentifier];
}

+ (BOOL)isSecureDownloadUrl:(NSString *)downloadUrl {
    if (downloadUrl == nil) {
        return NO;
    }
    NSURL *url = [NSURL URLWithString:downloadUrl];
    if (url == nil || url.scheme == nil) {
        return NO;
    }
    NSString *scheme = [url.scheme lowercaseString];
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
#if kREQUIRE_HTTPS
    return [scheme isEqualToString:@"https"];
#else
    return YES;
#endif
}

+ (NSString *)sanitizeFileName:(NSString *)fileName {
    if (fileName == nil || [fileName isKindOfClass:[NSNull class]]) {
        return @"resource_update.zip";
    }
    NSString *sanitized = [fileName lastPathComponent];
    if (sanitized.length == 0) {
        return @"resource_update.zip";
    }
    return sanitized;
}

+ (NSString *)resolveSecureTargetPath:(NSString *)targetPath documentRoot:(NSString *)documentRoot error:(NSError **)error {
    NSString *defaultPath = [documentRoot stringByAppendingPathComponent:@"www"];
    if (targetPath == nil || [targetPath isKindOfClass:[NSNull class]]
        || [targetPath stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length == 0) {
        return defaultPath;
    }
    
    NSString *canonicalTarget = [targetPath stringByStandardizingPath];
    NSString *canonicalRoot = [documentRoot stringByStandardizingPath];
    if (![EgovResourceUpdate isPath:canonicalTarget withinDirectory:canonicalRoot]) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"EgovResourceUpdate"
                                         code:12
                                     userInfo:@{NSLocalizedDescriptionKey: @"Target path outside app documents directory"}];
        }
        return nil;
    }
    return canonicalTarget;
}

+ (BOOL)isPath:(NSString *)path withinDirectory:(NSString *)directory {
    if (path == nil || directory == nil) {
        return NO;
    }
    if ([path isEqualToString:directory]) {
        return YES;
    }
    return [path hasPrefix:[directory stringByAppendingString:@"/"]];
}

+ (NSString *)computeSha256HexForFileAtPath:(NSString *)filePath {
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (handle == nil) {
        return nil;
    }
    
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    
    while (YES) {
        @autoreleasepool {
            NSData *data = [handle readDataOfLength:8192];
            if (data.length == 0) {
                break;
            }
            CC_SHA256_Update(&context, data.bytes, (CC_LONG)data.length);
        }
    }
    [handle closeFile];
    
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    
    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    return hash;
}

+(id) loadFromUserDefaults:(id)key {
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    id returnVals =nil;
    if (userDefaults && key) {
        returnVals = [userDefaults objectForKey:key];
    }
    return returnVals;
}

+(BOOL) saveToUserDefaults:(id)object forKey:(id)key {
    BOOL returnVal = NO;
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    @synchronized(userDefaults) {
        if (userDefaults && key && object) {
            [userDefaults setObject:object forKey:key];
        } else {
            [userDefaults removeObjectForKey:key];
        }
        returnVal = [userDefaults synchronize];
    }
    return returnVal;
}


- (void)initDialogView:(NSString*)message {
    
    self.labelMessage = [[UILabel alloc] initWithFrame:CGRectMake(10, 10, 240, 25)];
    [self.labelMessage setText:message];
    [self.labelMessage setTextAlignment:NSTextAlignmentCenter];
    
    self.progressView = [[UIProgressView alloc] initWithFrame:CGRectMake(20.0f, 70.0f, 220.0f, 30.0f)];
    [self.progressView setProgressViewStyle:UIProgressViewStyleBar];
    self.progressView.progress = 0.05f;
    
    UIView *infoView = [[UIView alloc] initWithFrame:CGRectMake(30.0f, 30.0f, 260.0f, 100.0f)];
    infoView.layer.cornerRadius = 10.0;
    infoView.layer.masksToBounds = YES;
    infoView.center = CGPointMake([[UIScreen mainScreen] bounds].size.width/ 2, [[UIScreen mainScreen] bounds].size.height / 2);
    infoView.backgroundColor = [UIColor whiteColor];
    [infoView addSubview:self.labelMessage];
    [infoView addSubview:self.progressView];
    
    self.dialogView = [[UIView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.dialogView.backgroundColor = [[UIColor grayColor] colorWithAlphaComponent:0.85f];
    [self.dialogView addSubview:infoView];
    
    [self.viewController.view addSubview:self.dialogView];
    
    self.dialogView.hidden = YES;
    
}

-(void) dialogView:(NSString*)command progress:(float)progressValue {
    if ([command isEqualToString:@"show"]) {
        self.dialogView.hidden = NO;
    } else if ([command isEqualToString:@"hide"]) {
        self.dialogView.hidden = YES;
    } else if ([command isEqualToString:@"progress"]) {
        self.progressView.progress = progressValue;
    }
}

-(void) setDialogMesage:(NSString*)message {
    self.labelMessage.text = message;
}

@end
