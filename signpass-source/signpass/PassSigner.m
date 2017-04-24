/*
 <codex><abstract>signpass</abstract></codex>
 */

#import "PassSigner.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#define PASS_IDENTITY_PREFIX @"Pass Type ID: "


void PSPrintLine(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *string = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    fprintf(stdout, "%s\n", [string UTF8String]);
    [string release];
}



@interface NSData(SHA1Hashing)
- (NSString *)SHA1HashString;
@end

@implementation NSData(SHA1Hashing)

// Returns the SHA1 hash of a data as a string
- (NSString *)SHA1HashString {
    
    // Generate the hash.
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    if(!CC_SHA1([self bytes], (CC_LONG)[self length], sha1)) {
        return nil;
    }
    
    // Append the bytes in the correct format.
    NSMutableString * hashedResult = [[NSMutableString alloc] init];
    for (unsigned i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hashedResult appendFormat:@"%02x", sha1[i]];    
    }
    return [hashedResult autorelease];
}

@end

@implementation PassSigner

+ (SecIdentityRef)passSigningIdentityRef:(NSString*)passTypeIdentifier
{
    OSStatus status;
    
    NSDictionary* matchingDictionary = @{ (NSString*)kSecClass : (NSString*)kSecClassIdentity, (NSString*)kSecMatchSubjectEndsWith : passTypeIdentifier, (NSString*)kSecReturnRef: (NSNumber*)kCFBooleanTrue};
    CFTypeRef result;
    
    status = SecItemCopyMatching((CFDictionaryRef) matchingDictionary, &result);

    if (status == 0)
        return (SecIdentityRef)[(id)result autorelease];
    else
        return nil;
}

+ (NSString*)passTypeIdentifierForPassAtURL:(NSURL*)passURL
{
    NSError* error = nil;
    NSURL* passJSONURL = [passURL URLByAppendingPathComponent:@"pass.json"];
    NSData* passData = [NSData dataWithContentsOfURL:passJSONURL];
    NSDictionary* passDictionary = [NSJSONSerialization JSONObjectWithData:passData options:0 error:&error];
    
    NSString* passTypeIdentifier = [passDictionary objectForKey:@"passTypeIdentifier"];
    
    return passTypeIdentifier;
}

+ (void)signPassWithURL:(NSURL *)passURL certSuffix:(NSString*)certSuffix outputURL:(NSURL *)outputURL zip:(BOOL)zip {
        
    // Dictionary to store our manifest hashes
    NSMutableDictionary *manifestDictionary = [[NSMutableDictionary alloc] init];
    
    // Temporary files
    NSFileManager *defaultManager = [NSFileManager defaultManager];
    NSString *temporaryDirectory = NSTemporaryDirectory();
    NSString *temporaryPath = [temporaryDirectory stringByAppendingPathComponent:[passURL lastPathComponent]];
    NSURL *tempURL = [NSURL fileURLWithPath:temporaryPath];
    
    NSError *error = nil;
    
    // Make sure we're starting fresh
    [defaultManager removeItemAtURL:tempURL error:&error];
    
    // Copy the pass to the temporary spot
    if (![defaultManager copyItemAtURL:passURL toURL:tempURL error:&error]) {
        NSLog(@"error: %@", [error localizedDescription]);
        exit(0);
    }
    
    // Build an enumerator to go through each file in the pass directory
    NSDirectoryEnumerator *enumerator = [defaultManager enumeratorAtURL:tempURL includingPropertiesForKeys:nil options:0 errorHandler:nil];
    
    // For each file in the pass directory...
    for (NSURL *theURL in enumerator) {
        NSNumber *isRegularFileNum = nil;
        NSError *error = nil;
        
        // Don't allow oddities like symbolic links
        if (![theURL getResourceValue:&isRegularFileNum forKey:NSURLIsRegularFileKey error:&error] || ![isRegularFileNum boolValue]) {
            if (error) {
                NSLog(@"error: %@", [error localizedDescription]);
            }
            continue;
        }
        
        // Build a hash of the data.
        NSData *fileData = [NSData dataWithContentsOfURL:theURL];
        NSString *sha1Hash = [fileData SHA1HashString];
        
        // Build a key, relative to the root of the directory
        NSArray *basePathComponents = [tempURL pathComponents];
        NSArray *urlPathComponents = [theURL pathComponents];
        
        NSRange range;
        range.location = ([basePathComponents count] + 1);
        range.length = [urlPathComponents count] - ([basePathComponents count] + 1);
        NSArray *relativePathComponents = [urlPathComponents subarrayWithRange:range];
        
        NSString *relativePath = [NSString pathWithComponents:relativePathComponents];
        
        if (relativePath) {
            // Store the computed hash and key
            [manifestDictionary setObject:sha1Hash forKey:relativePath];
        }
    }
    
    // Write out the manifest dictionary
    NSURL *manifestURL = [tempURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:manifestDictionary options:NSJSONWritingPrettyPrinted error:nil];
    [jsonData writeToURL:manifestURL atomically:YES];
    NSLog (@"%@", manifestDictionary);
    [manifestDictionary release];
    
    OSStatus status;
    if (certSuffix == nil) {
        certSuffix = [PassSigner passTypeIdentifierForPassAtURL:passURL];
    }
    
    if (certSuffix == nil) {
        NSLog(@"Couldn't find a passTypeIdentifier in the pass");
        return;
    }
    
    SecIdentityRef identity = [PassSigner passSigningIdentityRef:certSuffix];

    if (identity == nil) {
        NSLog(@"Couldn't find an identity for %@", certSuffix);
        return;
    }
    
    //Sign manifest
    NSData *signedData = nil;
    size_t len = [jsonData length];
    const void *bytes = [jsonData bytes];
    
    status = CMSEncodeContent(identity,
                              NULL,
                              0,
                              TRUE,
                              kCMSAttrSigningTime,
                              bytes, 
                              len, 
                              (CFDataRef *)&signedData);
    
    if (status != noErr) {
        NSString *secError = (NSString *)[NSMakeCollectable(SecCopyErrorMessageString(status, NULL)) autorelease];
        NSLog(@"Could not sign manifest data: %@", secError);
    } else {
        // Write signature to disk
        NSURL *signature = [tempURL URLByAppendingPathComponent:@"signature"];
        [signedData writeToURL:signature atomically:YES];
    }
    
    //Zip if necessary
    if (zip) {
        NSTask* zipTask;
        
        // Make a task to zip our contents
        zipTask = [[NSTask alloc] init];
        [zipTask setLaunchPath:@"/usr/bin/zip"];
        [zipTask setCurrentDirectoryPath:[tempURL path]];

        NSArray *argsArray = [NSArray arrayWithObjects:@"-r", @"-q", [outputURL path], @".", nil];
        [zipTask setArguments:argsArray];
        
        // Fire and wait. 
        [zipTask launch];
        [zipTask waitUntilExit];
        [zipTask release];
    }
}

+ (void)verifyPassSignatureWithURL:(NSURL *)passURL {
    
    if (passURL) {
        // get a temporary place to unpack the pass
        NSString *temporaryDirectory = NSTemporaryDirectory();
        NSString *temporaryPath = [temporaryDirectory stringByAppendingPathComponent:[passURL lastPathComponent]];
        NSURL *tempURL = [NSURL fileURLWithPath:temporaryPath];
        
        // unzip the pass there
        NSTask *unzipTask = [[NSTask alloc] init];
        [unzipTask setLaunchPath:@"/usr/bin/unzip"];
        NSArray *argsArray = [NSArray arrayWithObjects:@"-q", @"-o", [passURL path], @"-d", [tempURL path], nil];
        [unzipTask setArguments:argsArray];
        [unzipTask launch];
        [unzipTask waitUntilExit];
        
        if ([unzipTask terminationStatus] == 0) {
            BOOL valid = [self validateManifestAtURL:tempURL] && [self validateSignatureAtURL:tempURL];
            if (valid) {
                PSPrintLine(@"\n*** SUCCEEDED ***");
            } else {
                PSPrintLine(@"\n*** FAILED ***");
            }
        }
        
        [unzipTask release];
    }
}

+ (BOOL)validateSignatureAtURL:(NSURL *)tempURL {
    BOOL valid = NO;
    
    // pick up the manifest and signature
    NSURL *signatureURL = [tempURL URLByAppendingPathComponent:@"signature"];
    NSURL *manifestURL = [tempURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *signature = [NSData dataWithContentsOfURL:signatureURL];
    NSData *manifest = [NSData dataWithContentsOfURL:manifestURL];
    
    // set up a cms decoder
    CMSDecoderRef decoder;
    CMSDecoderCreate(&decoder);
    CMSDecoderSetDetachedContent(decoder, (CFDataRef)manifest);
    CMSDecoderUpdateMessage(decoder, [signature bytes], [signature length]);
    CMSDecoderFinalizeMessage(decoder);
    
    CMSSignerStatus status;
    OSStatus result;
    
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust;
    
    // obtain the status
    CMSDecoderCopySignerStatus(decoder, 0, policy, NO, &status, &trust, &result);
    
    if (kCMSSignerValid == status) {
        PSPrintLine(@"Signature valid.");
        
        // validate trust chain
        SecTrustResultType trustResult;
        SecTrustEvaluate(trust, &trustResult);
        
        if (kSecTrustResultUnspecified == trustResult) {
            CFArrayRef certs;
            CMSDecoderCopyAllCerts(decoder, &certs);
            
            BOOL foundWWDRCert = NO;

            if (CFArrayGetCount(certs) > 0) {
                PSPrintLine(@"Certificates: (");
                for (CFIndex i=0; i < CFArrayGetCount(certs); i++) {
                    SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
                    CFStringRef commonName = NULL;
                    SecCertificateCopyCommonName(cert, &commonName);
                    PSPrintLine(@"\t%ld: %@", i, commonName);
                    
                    // one of the certs needs to be the WWDR one
                    if (!CFStringCompare(commonName, CFSTR("Apple Worldwide Developer Relations Certification Authority"), 0)) {
                        foundWWDRCert = YES;
                    }
                    if (commonName) {
                        CFRelease(commonName);
                    }
                }
                PSPrintLine(@")");
            }
            
            if (certs) {
                CFRelease(certs);
            }
            
            if (foundWWDRCert) {
                PSPrintLine(@"Trust chain is valid.");
                valid = YES;
            } else {
                PSPrintLine(@"The Apple WWDR Intermediate Certificate must be included in the signature.\nhttps://developer.apple.com/certificationauthority/AppleWWDRCA.cer");
            }
            
        } else {
            // trust chain wasn't verified
            CFArrayRef propertiesArray = SecTrustCopyProperties(trust);
            PSPrintLine(@"Error validating trust chain:");
            for (CFIndex i=0; i < CFArrayGetCount(propertiesArray); i++) {
                CFDictionaryRef properties = CFArrayGetValueAtIndex(propertiesArray, i);
                CFStringRef title = CFDictionaryGetValue((CFDictionaryRef)properties, kSecPropertyTypeTitle);
                CFStringRef error = CFDictionaryGetValue((CFDictionaryRef)properties, kSecPropertyTypeError);
                PSPrintLine(@"\t%@: %@", (NSString *)title, (NSString *)error);
            }
            if (propertiesArray) {
                CFRelease(propertiesArray);
            }
        }
        
        if (trust) CFRelease(trust);
        
    } else {
        // signature wasn't valid
        CFStringRef errorString = SecCopyErrorMessageString(result, NULL);
        PSPrintLine(@"Error validating signature: %@", errorString);
        if (errorString) {
            CFRelease(errorString);
        }
    }
    
    if (decoder) {
        CFRelease(decoder);
    }

    return valid;
}

+ (BOOL)validateManifestAtURL:(NSURL *)passURL {
    BOOL valid = YES;
    
    NSURL *manifestURL = [passURL URLByAppendingPathComponent:@"manifest.json"];
    NSData *manifestData = [NSData dataWithContentsOfURL:manifestURL];
    NSError *error = NULL;
    NSMutableDictionary *manifest = [[NSJSONSerialization JSONObjectWithData:manifestData options:0 error:&error] mutableCopy];
    if (manifest) {
        NSFileManager *defaultManager = [NSFileManager defaultManager];
        
        NSDirectoryEnumerator *enumerator = [defaultManager enumeratorAtURL:passURL
                                                 includingPropertiesForKeys:@[ NSURLFileSizeKey, NSURLIsDirectoryKey ]
                                                                    options:0
                                                               errorHandler:nil];
        
        for (NSURL *theURL in enumerator) {
            NSNumber *isDirectoryNum = nil;
            if ([theURL getResourceValue:&isDirectoryNum forKey:NSURLIsDirectoryKey error:NULL] && [isDirectoryNum boolValue]) {
                continue;
            }
            
            NSArray *basePathComponents = [[passURL URLByResolvingSymlinksInPath] pathComponents];
            NSArray *urlPathComponents = [[theURL URLByResolvingSymlinksInPath] pathComponents];
            
            NSRange range;
            range.location = ([basePathComponents count]);
            range.length = [urlPathComponents count] - ([basePathComponents count]);
            NSArray *relativePathComponents = [urlPathComponents subarrayWithRange:range];
            
            NSString *relativePath = [NSString pathWithComponents:relativePathComponents];
            
            //ignore the signature and manifest files
            if (![relativePath isEqualToString:@"manifest.json"] &&
                ![relativePath isEqualToString:@"signature"]) {
                
                NSString *manifestSHA1 = [manifest objectForKey:relativePath];
                if (!manifestSHA1) {
                    PSPrintLine(@"No entry in manifest for file %@", relativePath);
                    valid = NO;
                    break;
                }
                
                NSData *fileData = [[NSData alloc] initWithContentsOfURL:theURL];
                NSString *hexSHA1 = [fileData SHA1HashString];
                
                if (![hexSHA1 isEqualToString:manifestSHA1]) {
                    PSPrintLine(@"For file %@, manifest's listed SHA1 hash %@ doesn't match computed hash, %@", relativePath, manifestSHA1, hexSHA1);
                    [fileData release];
                    valid = NO;
                    break;
                }
                
                if (relativePath) {
                    [manifest removeObjectForKey:relativePath];
                }
                [fileData release];
            }
            
            BOOL isSymLink = [[[defaultManager attributesOfItemAtPath:[passURL absoluteString] error:nil] objectForKey:NSFileType] isEqualToString:NSFileTypeSymbolicLink];
            
            if (isSymLink) {
                PSPrintLine(@"Pass contains a symlink, %@, which is illegal", relativePath);
                break;
                valid = NO;
            }
        }
        
        if (valid && [manifest count]) {
            PSPrintLine(@"Pass is missing files listed in the manifest, %@", manifest);
            valid = NO;
        }
    } else {
        PSPrintLine(@"Manifest didn't parse. %@", [error localizedDescription]);
    }
    
    [manifest release];
    
    return valid;
}

@end
