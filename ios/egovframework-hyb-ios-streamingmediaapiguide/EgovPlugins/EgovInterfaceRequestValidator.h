//
//  EgovInterfaceRequestValidator.h
//  Validates EgovInterface requests before they reach the server.
//

#import <Foundation/Foundation.h>

extern NSString * const EgovInterfaceErrorSecureUrl;
extern NSString * const EgovInterfaceErrorUri;
extern NSString * const EgovInterfaceErrorParam;
extern NSString * const EgovInterfaceErrorAccept;

@interface EgovInterfaceRequestValidator : NSObject

+ (BOOL)isSecureServerUrl:(NSString *)serverUrl;
+ (NSString *)normalizeUri:(NSString *)rawUri error:(NSError **)error;
+ (NSDictionary *)sanitizeParametersForMethod:(NSString *)httpMethod
                                   parameters:(NSDictionary *)parameters
                                        error:(NSError **)error;
+ (id)sanitizeResponseObject:(id)responseObject;
+ (NSString *)sanitizeResponseString:(NSString *)body;

@end
