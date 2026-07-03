//
//  EgovFileOpenerRequestValidator.m
//

#import "EgovFileOpenerRequestValidator.h"
#import "EgovInterfaceRequestValidator.h"
#import "EGovComModule.h"

NSString * const EgovFileOpenerErrorSecureUrl = @"HTTPS server URL is required";
NSString * const EgovFileOpenerErrorUri = @"Download URI is not allowed";
NSString * const EgovFileOpenerErrorFilename = @"File name is invalid";
NSString * const EgovFileOpenerErrorTargetPath = @"Target path is not allowed";

static const NSInteger kMaxUriLength = 256;
static const NSInteger kMaxFilenameLength = 255;
static NSString * const kFopPrefix = @"/fop/";

static NSSet *allowedExtensions(void) {
    static NSSet *extensions;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        extensions = [NSSet setWithObjects:
                      @"txt", @"pdf", @"doc", @"docx", @"xls", @"xlsx", @"ppt", @"pptx", @"zip",
                      @"jpg", @"jpeg", @"png", @"gif", @"bmp", @"mp3", @"mp4", @"m4a", @"wav", @"3gp", @"hwp", nil];
    });
    return extensions;
}

static NSSet *dangerousExtensions(void) {
    static NSSet *extensions;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        extensions = [NSSet setWithObjects:
                      @"html", @"htm", @"js", @"jsx", @"mjs", @"jsp", @"php", @"asp", @"aspx",
                      @"sh", @"bash", @"bat", @"cmd", @"exe", @"apk", @"dex", @"so", @"dylib", @"xml", @"plist", nil];
    });
    return extensions;
}

@implementation EgovFileOpenerRequestValidator

+ (NSString *)buildDownloadUrlWithServerUrl:(NSString *)serverUrl
                                        uri:(NSString *)rawUri
                                      error:(NSError **)error {
    if (![EgovInterfaceRequestValidator isSecureServerUrl:serverUrl]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:1
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorSecureUrl}];
        }
        return nil;
    }

    NSString *normalizedUri = [self normalizeDownloadUri:rawUri error:error];
    if (normalizedUri == nil) {
        return nil;
    }
    return [NSString stringWithFormat:@"%@%@", serverUrl, normalizedUri];
}

+ (NSString *)normalizeDownloadUri:(NSString *)rawUri error:(NSError **)error {
    if (rawUri == nil || [[rawUri stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length] == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:2
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorUri}];
        }
        return nil;
    }

    NSString *trimmed = [rawUri stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *path = trimmed;
    NSString *query = nil;

    NSRange queryRange = [trimmed rangeOfString:@"?"];
    if (queryRange.location != NSNotFound) {
        path = [trimmed substringToIndex:queryRange.location];
        query = [trimmed substringFromIndex:queryRange.location + 1];
    }
    NSRange fragmentRange = [path rangeOfString:@"#"];
    if (fragmentRange.location != NSNotFound) {
        path = [path substringToIndex:fragmentRange.location];
    }

    NSCharacterSet *uriPathCharset = [NSCharacterSet characterSetWithCharactersInString:
                                      @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-"];
    NSCharacterSet *uriQueryCharset = [NSCharacterSet characterSetWithCharactersInString:
                                       @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./=&%-"];
    NSCharacterSet *invertedPath = [uriPathCharset invertedSet];
    NSCharacterSet *invertedQuery = [uriQueryCharset invertedSet];

    if (path.length > kMaxUriLength
        || [path containsString:@".."]
        || [path containsString:@"\\"]
        || [path containsString:@"%"]
        || ![path hasPrefix:@"/"]
        || ![path hasPrefix:kFopPrefix]
        || [path rangeOfCharacterFromSet:invertedPath].location != NSNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:3
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorUri}];
        }
        return nil;
    }

    if (query != nil) {
        if (query.length > kMaxUriLength || [query rangeOfCharacterFromSet:invertedQuery].location != NSNotFound) {
            if (error) {
                *error = [NSError errorWithDomain:@"EgovFileOpener" code:4
                                         userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorUri}];
            }
            return nil;
        }
        return [NSString stringWithFormat:@"%@?%@", path, query];
    }
    return path;
}

+ (NSString *)normalizeFileName:(NSString *)rawFileName error:(NSError **)error {
    if (rawFileName == nil || [[rawFileName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length] == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:5
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorFilename}];
        }
        return nil;
    }

    NSString *fileName = [[rawFileName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                          stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
    NSRange slashRange = [fileName rangeOfString:@"/" options:NSBackwardsSearch];
    if (slashRange.location != NSNotFound) {
        fileName = [fileName substringFromIndex:slashRange.location + 1];
    }

    if (fileName.length > kMaxFilenameLength
        || [fileName containsString:@".."]
        || [fileName containsString:@"/"]
        || [fileName containsString:@"\\"]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:6
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorFilename}];
        }
        return nil;
    }

    NSString *extension = [self extensionForFileName:fileName];
    if (extension.length == 0
        || [dangerousExtensions() containsObject:extension]
        || ![allowedExtensions() containsObject:extension]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:7
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorFilename}];
        }
        return nil;
    }
    return fileName;
}

+ (NSString *)normalizeStoredFileName:(NSString *)rawStoredFileName error:(NSError **)error {
    if (rawStoredFileName == nil || [[rawStoredFileName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length] == 0) {
        return @"";
    }

    NSString *storedFileName = [rawStoredFileName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSCharacterSet *filenameCharset = [NSCharacterSet characterSetWithCharactersInString:
                                       @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    NSCharacterSet *invertedFilename = [filenameCharset invertedSet];

    if (storedFileName.length > kMaxFilenameLength
        || [storedFileName containsString:@".."]
        || [storedFileName containsString:@"/"]
        || [storedFileName containsString:@"\\"]
        || [storedFileName rangeOfCharacterFromSet:invertedFilename].location != NSNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:8
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorFilename}];
        }
        return nil;
    }
    return storedFileName;
}

+ (NSString *)resolveSecureTargetDirectoryForPath:(NSString *)rawTargetPath error:(NSError **)error {
    NSString *normalizedPath = [self normalizePathPrefix:rawTargetPath];
    if (normalizedPath == nil) {
        NSArray *documentPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        normalizedPath = [[documentPaths firstObject] stringByAppendingPathComponent:@"www"];
    }

    NSString *canonicalPath = [normalizedPath stringByStandardizingPath];
    if (![self isPath:canonicalPath withinAllowedAppDirectory]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:9
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorTargetPath}];
        }
        return nil;
    }

    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL isDirectory = NO;
    if (![fileManager fileExistsAtPath:canonicalPath isDirectory:&isDirectory]) {
        NSError *createError = nil;
        if (![fileManager createDirectoryAtPath:canonicalPath
                     withIntermediateDirectories:YES
                                      attributes:nil
                                           error:&createError]) {
            if (error) {
                *error = createError;
            }
            return nil;
        }
        isDirectory = YES;
    } else if (!isDirectory) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:10
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorTargetPath}];
        }
        return nil;
    }
    return canonicalPath;
}

+ (NSString *)resolveSecureTargetFilePathForDirectory:(NSString *)targetDirectory
                                             fileName:(NSString *)fileName
                                                error:(NSError **)error {
    NSString *secureDirectory = [self resolveSecureTargetDirectoryForPath:targetDirectory error:error];
    if (secureDirectory == nil) {
        return nil;
    }

    NSString *targetFilePath = [[secureDirectory stringByAppendingPathComponent:fileName] stringByStandardizingPath];
    if (![self isPath:targetFilePath withinDirectory:secureDirectory]) {
        if (error) {
            *error = [NSError errorWithDomain:@"EgovFileOpener" code:11
                                     userInfo:@{NSLocalizedDescriptionKey: EgovFileOpenerErrorTargetPath}];
        }
        return nil;
    }
    return targetFilePath;
}

+ (NSString *)normalizePathPrefix:(NSString *)rawTargetPath {
    if (rawTargetPath == nil || [rawTargetPath isKindOfClass:[NSNull class]]) {
        return nil;
    }
    NSString *normalized = [rawTargetPath stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (normalized.length == 0 || [normalized caseInsensitiveCompare:@"null"] == NSOrderedSame) {
        return nil;
    }
    if ([normalized hasPrefix:@"file://"]) {
        normalized = [normalized substringFromIndex:[@"file://" length]];
    }
    return normalized;
}

+ (BOOL)isPath:(NSString *)path withinDirectory:(NSString *)directory {
    if (path == nil || directory == nil) {
        return NO;
    }
    NSString *canonicalPath = [path stringByStandardizingPath];
    NSString *canonicalDir = [directory stringByStandardizingPath];
    if ([canonicalPath isEqualToString:canonicalDir]) {
        return YES;
    }
    return [canonicalPath hasPrefix:[canonicalDir stringByAppendingString:@"/"]];
}

+ (BOOL)isPath:(NSString *)path withinAllowedAppDirectory {
    NSArray *documentPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSArray *cachePaths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    NSArray *libraryPaths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);

    for (NSString *root in documentPaths) {
        if ([self isPath:path withinDirectory:root]) {
            return YES;
        }
    }
    for (NSString *root in cachePaths) {
        if ([self isPath:path withinDirectory:root]) {
            return YES;
        }
    }
    for (NSString *root in libraryPaths) {
        if ([self isPath:path withinDirectory:root]) {
            return YES;
        }
    }
    return NO;
}

+ (NSString *)extensionForFileName:(NSString *)fileName {
    NSString *extension = [[fileName pathExtension] lowercaseString];
    return extension == nil ? @"" : extension;
}

@end
