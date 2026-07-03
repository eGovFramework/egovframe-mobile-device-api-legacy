//
//  EgovZip.m
//  DEVICEAPI
//
//  Created by shin yongho on 2016. 6. 24..
//
//

#import "EgovZip.h"

static const unsigned long long kMaxUncompressedZipSize = 100ULL * 1024ULL * 1024ULL;
static const int kMaxCompressionRatio = 100;

@interface EgovZipSecureDelegate : NSObject <SSZipArchiveDelegate>
@property (nonatomic, copy) NSString *destinationPath;
@property (nonatomic, assign) unsigned long long totalUncompressedSize;
@property (nonatomic, assign) BOOL rejected;
@end

@implementation EgovZipSecureDelegate

- (BOOL)zipArchiveShouldUnzipFileAtIndex:(NSInteger)fileIndex
                             totalFiles:(NSInteger)totalFiles
                            archivePath:(NSString *)archivePath
                               fileInfo:(unz_file_info)fileInfo {
    if (self.rejected) {
        return NO;
    }
    if (fileInfo.uncompressed_size > 0 && fileInfo.compressed_size > 0) {
        unsigned long long ratio = fileInfo.uncompressed_size / fileInfo.compressed_size;
        if (ratio > kMaxCompressionRatio) {
            self.rejected = YES;
            return NO;
        }
    }
    if (fileInfo.uncompressed_size > 0) {
        self.totalUncompressedSize += fileInfo.uncompressed_size;
        if (self.totalUncompressedSize > kMaxUncompressedZipSize) {
            self.rejected = YES;
            return NO;
        }
    }
    return YES;
}

- (void)zipArchiveDidUnzipFileAtIndex:(NSInteger)fileIndex
                           totalFiles:(NSInteger)totalFiles
                          archivePath:(NSString *)archivePath
                     unzippedFilePath:(NSString *)unzippedFilePath {
    if (![EgovZip isPath:unzippedFilePath withinDirectory:self.destinationPath]) {
        self.rejected = YES;
        [[NSFileManager defaultManager] removeItemAtPath:unzippedFilePath error:nil];
    }
}

@end

@implementation EgovZip

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

+ (BOOL)validateDestinationPath:(NSString *)destinationPath {
    if (destinationPath == nil || destinationPath.length == 0) {
        return NO;
    }
    NSArray *documentPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentRoot = [documentPaths firstObject];
    return [self isPath:destinationPath withinDirectory:documentRoot];
}

+ (BOOL) doUnZipFileAtPath:(NSString*)zipFilePath toDestination:(NSString*)destinationPath {
    if (![self validateDestinationPath:destinationPath]) {
        NSLog(@"unzip rejected: destination outside app documents directory");
        return NO;
    }
    
    EgovZipSecureDelegate *delegate = [[EgovZipSecureDelegate alloc] init];
    delegate.destinationPath = [destinationPath stringByStandardizingPath];
    delegate.totalUncompressedSize = 0;
    delegate.rejected = NO;
    
    NSError *error = nil;
    BOOL ret = [SSZipArchive unzipFileAtPath:zipFilePath
                               toDestination:destinationPath
                          preserveAttributes:YES
                                   overwrite:YES
                                    password:nil
                                       error:&error
                                    delegate:delegate];
    if (delegate.rejected) {
        NSLog(@"unzip rejected: insecure ZIP entry detected");
        return NO;
    }
    NSLog(@"unzip result =: %@", (ret ? @"YES": @"NO"));
    if (error != nil) {
        NSLog(@"unzip error = %@", error.localizedDescription);
    }
    return ret && !delegate.rejected;
}

- (void) unzip:(CDVInvokedUrlCommand *)command {
    
    NSURL *sourcePath = [NSURL URLWithString:[command.arguments objectAtIndex:0]];
    NSURL *targetDir = [NSURL URLWithString:[command.arguments objectAtIndex:1]];
    self.callbackID = command.callbackId;
    
    NSLog(@"sourcePath : %@", sourcePath.path);
    NSLog(@"targetDir : %@", targetDir.path);
    
    if (![EgovZip validateDestinationPath:targetDir.path]) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:nil];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
        return;
    }
    
    BOOL ret = [EgovZip doUnZipFileAtPath:sourcePath.path toDestination:targetDir.path];
    NSLog(@"zip result =: %@", (ret ? @"YES": @"NO"));
    
    if (ret==YES) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:nil];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
        
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:nil];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
    
}

- (void) zip:(CDVInvokedUrlCommand *)command {
    
    NSURL *sourcePath = [NSURL URLWithString:[command.arguments objectAtIndex:0]];
    NSURL *targetDir = [NSURL URLWithString:[command.arguments objectAtIndex:1]];
    self.callbackID = command.callbackId;
    
    NSLog(@"sourcePath : %@", sourcePath.path);
    NSLog(@"targetDir : %@", targetDir.path);
    
    BOOL ret = [SSZipArchive createZipFileAtPath:targetDir.path withContentsOfDirectory:sourcePath.path];
    NSLog(@"Unzip result =: %@", (ret ? @"YES": @"NO"));
    
    if (ret==YES) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:nil];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
        
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:nil];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackID];
    }
    
}
@end
