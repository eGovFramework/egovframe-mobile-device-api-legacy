//
//  EgovInterface.m
//

#import "EgovInterface.h"
#import "EgovInterfaceRequestValidator.h"

@interface EgovInterface()
{
}
@property(nonatomic, retain) NSString *m_arguments;
@property(nonatomic, retain) NSMutableDictionary *m_params;
@end

@implementation EgovInterface

@synthesize callbackID;
@synthesize m_arguments, m_params;

#pragma mark - plugin method

- (void)echo:(CDVInvokedUrlCommand*)command
{
    NSString *message = [command.arguments objectAtIndex:0];
    [[[UIAlertView alloc] initWithTitle:@"iOS검색" message:message delegate:nil cancelButtonTitle:@"취소" otherButtonTitles:@"확인", nil] show];
}

- (void)submitAsynchronous:(CDVInvokedUrlCommand*)command;
{
    NSString *arguments = [command.arguments objectAtIndex:1];
    NSMutableDictionary *params = [command.arguments objectAtIndex:0];
    self.callbackID = command.callbackId;

    if (![EgovInterfaceRequestValidator isSecureServerUrl:kSERVER_URL]) {
        [self sendError:EgovInterfaceErrorSecureUrl];
        return;
    }

    NSError *validationError = nil;
    NSString *normalizedUri = [EgovInterfaceRequestValidator normalizeUri:arguments error:&validationError];
    if (validationError != nil) {
        [self sendError:[validationError localizedDescription]];
        return;
    }

    NSDictionary *sanitizedParams = [EgovInterfaceRequestValidator sanitizeParametersForMethod:@"POST"
                                                                                  parameters:params
                                                                                       error:&validationError];
    if (validationError != nil) {
        [self sendError:[validationError localizedDescription]];
        return;
    }

    self.m_arguments = normalizedUri;
    self.m_params = [NSMutableDictionary dictionaryWithDictionary:sanitizedParams];

    NSString *requestUrl = [NSString stringWithFormat:@"%@%@", kSERVER_URL, normalizedUri];
    EGovComModule *m_module = [[EGovComModule alloc] initWithURL:requestUrl delegate:self];

    for (NSString *str in self.m_params) {
        NSString *value = [self.m_params objectForKey:str];
        [m_module addPost:value key:str];
    }

    [m_module startAsynchronous];
}

- (void)geturl:(CDVInvokedUrlCommand *)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:kSERVER_URL];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)sendError:(NSString *)message {
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:message];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
}

#pragma mark - EGovModuleDelegate
- (void)onNetworkStarted
{
    NSLog(@"network started");
}

- (void)onNetworkFailed:(NSError*)error
{
    NSMutableString *stringToReturn = [NSMutableString stringWithString: @"StringReceived:"];
    [stringToReturn appendString:[NSString stringWithFormat:@"%@", error.description]];

    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                      messageAsString:[stringToReturn stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
}

- (void)onNetworkFinished:(NSData*)responseData responseString:(NSString*)responseString responseStatusCode:(NSInteger)responseStatusCode
{
    if (responseStatusCode == kSERVER_OK) {
        NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:responseData options:NSJSONReadingMutableContainers error:nil];
        if (dic != nil) {
            id sanitized = [EgovInterfaceRequestValidator sanitizeResponseObject:dic];
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:sanitized];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
            return;
        }
        NSString *sanitizedBody = [EgovInterfaceRequestValidator sanitizeResponseString:responseString];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:sanitizedBody];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    } else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsString:[[NSString stringWithFormat:@"%d", responseStatusCode] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
}

@end
