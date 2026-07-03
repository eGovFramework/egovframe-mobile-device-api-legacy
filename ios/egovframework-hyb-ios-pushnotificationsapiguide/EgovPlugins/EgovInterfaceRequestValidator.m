//
//  EgovInterfaceRequestValidator.m
//

#import "EgovInterfaceRequestValidator.h"
#import "EGovComModule.h"

NSString * const EgovInterfaceErrorSecureUrl = @"HTTPS server URL is required";
NSString * const EgovInterfaceErrorUri = @"URI is not allowed";
NSString * const EgovInterfaceErrorParam = @"Parameter input is invalid";
NSString * const EgovInterfaceErrorAccept = @"Accept type is invalid";

static const NSInteger kMaxUriLength = 256;
static const NSInteger kMaxParamCount = 32;
static const NSInteger kMaxParamKeyLength = 64;
static const NSInteger kMaxParamValueLength = 8192;

@implementation EgovInterfaceRequestValidator

+ (BOOL)isSecureServerUrl:(NSString *)serverUrl {
    if (serverUrl == nil || serverUrl.length == 0) {
        return NO;
    }
    NSURL *url = [NSURL URLWithString:[serverUrl stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
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

+ (NSString *)normalizeUri:(NSString *)rawUri error:(NSError **)error {
    if (rawUri == nil || [[rawUri stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length] == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:1 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorUri}];
        }
        return nil;
    }

    NSString *path = [rawUri stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSRange queryRange = [path rangeOfString:@"?"];
    if (queryRange.location != NSNotFound) {
        path = [path substringToIndex:queryRange.location];
    }
    NSRange fragmentRange = [path rangeOfString:@"#"];
    if (fragmentRange.location != NSNotFound) {
        path = [path substringToIndex:fragmentRange.location];
    }

    if (path.length > kMaxUriLength
        || [path containsString:@".."]
        || [path containsString:@"\\"]
        || [path containsString:@"%"]
        || ![path hasPrefix:@"/"]
        || ![self isValidUriPath:path]
        || ![self isAllowedUri:path]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:2 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorUri}];
        }
        return nil;
    }
    return path;
}

+ (NSDictionary *)sanitizeParametersForMethod:(NSString *)httpMethod
                                   parameters:(NSDictionary *)parameters
                                        error:(NSError **)error {
    NSMutableDictionary *sanitized = [NSMutableDictionary dictionary];
    if (parameters == nil) {
        return sanitized;
    }
    if (parameters.count > kMaxParamCount) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:3 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorParam}];
        }
        return nil;
    }

    for (NSString *key in parameters) {
        if (![self isValidParameterKey:key forMethod:httpMethod error:error]) {
            return nil;
        }
        NSString *value = [self normalizeParameterValue:[parameters objectForKey:key] error:error];
        if (value == nil) {
            return nil;
        }
        [sanitized setObject:value forKey:key];
    }
    return sanitized;
}

+ (id)sanitizeResponseObject:(id)responseObject {
    if ([responseObject isKindOfClass:[NSDictionary class]]) {
        return [self sanitizeDictionary:(NSDictionary *)responseObject];
    }
    if ([responseObject isKindOfClass:[NSArray class]]) {
        NSMutableArray *items = [NSMutableArray array];
        for (id item in (NSArray *)responseObject) {
            [items addObject:[self sanitizeResponseObject:item] ?: [NSNull null]];
        }
        return items;
    }
    return responseObject;
}

+ (NSString *)sanitizeResponseString:(NSString *)body {
    if (body == nil || body.length == 0) {
        return body;
    }
    NSString *masked = body;
    masked = [self replaceRegex:@"<userPw>[^<]*</userPw>" template:@"<userPw>****</userPw>" inString:masked ignoreCase:YES];
    masked = [self replaceRegex:@"<USER_PW>[^<]*</USER_PW>" template:@"<USER_PW>****</USER_PW>" inString:masked ignoreCase:YES];
    masked = [self replaceRegex:@"\"userPw\"\\s*:\\s*\"[^\"]*\"" template:@"\"userPw\":\"****\"" inString:masked ignoreCase:YES];
    masked = [self replaceRegex:@"\"USER_PW\"\\s*:\\s*\"[^\"]*\"" template:@"\"USER_PW\":\"****\"" inString:masked ignoreCase:YES];
    return masked;
}

#pragma mark - Private

+ (BOOL)isValidUriPath:(NSString *)path {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^/[a-zA-Z0-9][a-zA-Z0-9_./-]*$" options:0 error:nil];
    return [regex numberOfMatchesInString:path options:0 range:NSMakeRange(0, path.length)] > 0;
}

+ (BOOL)isAllowedUri:(NSString *)uri {
    NSArray *prefixes = @[
        @"/acl/", @"/cmr/", @"/cps/", @"/ctt/", @"/dvc/", @"/frw/", @"/gps/", @"/itf/",
        @"/mda/", @"/nwk/", @"/vbr/", @"/pus/", @"/fop/", @"/stm/", @"/bar/", @"/upd/", @"/jai/"
    ];
    for (NSString *prefix in prefixes) {
        if ([uri hasPrefix:prefix]) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)isValidParameterKey:(NSString *)key forMethod:(NSString *)httpMethod error:(NSError **)error {
    if (key == nil || key.length > kMaxParamKeyLength) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:4 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorParam}];
        }
        return NO;
    }
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^[a-zA-Z][a-zA-Z0-9_]*$" options:0 error:nil];
    if ([regex numberOfMatchesInString:key options:0 range:NSMakeRange(0, key.length)] == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:5 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorParam}];
        }
        return NO;
    }
    if ([httpMethod caseInsensitiveCompare:@"GET"] == NSOrderedSame) {
        NSString *lowerKey = [key lowercaseString];
        NSArray *blocked = @[@"userpw", @"password", @"passwd", @"pwd", @"secret", @"token", @"accesstoken", @"refreshtoken"];
        if ([blocked containsObject:lowerKey]) {
            if (error) {
                *error = [NSError errorWithDomain:@"EgovInterface" code:6 userInfo:@{NSLocalizedDescriptionKey: @"Sensitive parameter is not allowed in GET"}];
            }
            return NO;
        }
    }
    return YES;
}

+ (NSString *)normalizeParameterValue:(id)value error:(NSError **)error {
    if (value == nil || value == [NSNull null]) {
        return @"";
    }
    NSString *text = [NSString stringWithFormat:@"%@", value];
    if (text.length > kMaxParamValueLength || [text rangeOfString:@"\0"].location != NSNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovInterface" code:7 userInfo:@{NSLocalizedDescriptionKey: EgovInterfaceErrorParam}];
        }
        return nil;
    }
    return text;
}

+ (NSMutableDictionary *)sanitizeDictionary:(NSDictionary *)dictionary {
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithCapacity:dictionary.count];
    for (NSString *key in dictionary) {
        id value = [dictionary objectForKey:key];
        if ([key caseInsensitiveCompare:@"userPw"] == NSOrderedSame
            || [key caseInsensitiveCompare:@"USER_PW"] == NSOrderedSame) {
            [result setObject:@"****" forKey:key];
        } else if ([value isKindOfClass:[NSDictionary class]]) {
            [result setObject:[self sanitizeDictionary:value] forKey:key];
        } else if ([value isKindOfClass:[NSArray class]]) {
            [result setObject:[self sanitizeResponseObject:value] forKey:key];
        } else {
            [result setObject:value forKey:key];
        }
    }
    return result;
}

+ (NSString *)replaceRegex:(NSString *)pattern template:(NSString *)template inString:(NSString *)input ignoreCase:(BOOL)ignoreCase {
    NSRegularExpressionOptions options = ignoreCase ? NSRegularExpressionCaseInsensitive : 0;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:options error:nil];
    return [regex stringByReplacingMatchesInString:input options:0 range:NSMakeRange(0, input.length) withTemplate:template];
}

@end
