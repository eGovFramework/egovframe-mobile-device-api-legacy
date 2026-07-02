//
//  EgovFileOpenerRequestValidator.h
//

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString * const EgovFileOpenerErrorSecureUrl;
FOUNDATION_EXPORT NSString * const EgovFileOpenerErrorUri;
FOUNDATION_EXPORT NSString * const EgovFileOpenerErrorFilename;
FOUNDATION_EXPORT NSString * const EgovFileOpenerErrorTargetPath;

@interface EgovFileOpenerRequestValidator : NSObject

+ (NSString *)buildDownloadUrlWithServerUrl:(NSString *)serverUrl
                                        uri:(NSString *)rawUri
                                      error:(NSError **)error;

+ (NSString *)normalizeFileName:(NSString *)rawFileName error:(NSError **)error;

+ (NSString *)normalizeStoredFileName:(NSString *)rawStoredFileName error:(NSError **)error;

+ (NSString *)resolveSecureTargetDirectoryForPath:(NSString *)rawTargetPath
                                            error:(NSError **)error;

+ (NSString *)resolveSecureTargetFilePathForDirectory:(NSString *)targetDirectory
                                             fileName:(NSString *)fileName
                                                error:(NSError **)error;

@end
