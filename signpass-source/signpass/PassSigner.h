/*
 <codex><abstract>signpass</abstract></codex>
 */

#import <Foundation/Foundation.h>

void PSPrintLine(NSString *format, ...);

@interface PassSigner : NSObject

+ (void)signPassWithURL:(NSURL *)passURL certSuffix:(NSString*)certSuffix outputURL:(NSURL *)outputURL zip:(BOOL)zip;
+ (void)verifyPassSignatureWithURL:(NSURL *)passURL;
@end
