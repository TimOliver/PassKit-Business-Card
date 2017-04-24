/*
 <codex><abstract>signpass</abstract></codex>
 */

#import <Foundation/Foundation.h>
#import "PassSigner.h"

int main (int argc, const char * argv[])
{
    @autoreleasepool {
                
        NSString *passPath = nil;
        NSString *certSuffix = nil;
        NSString *outputPath = nil;
        NSString *verifyPath = nil;
        
        NSArray *args = [[NSProcessInfo processInfo] arguments];
        
        if ([args containsObject:@"-p"] && ![args containsObject:@"-v"]) {
            NSUInteger index = [args indexOfObject:@"-p"];
            if ((index + 1) < [args count]) { 
                passPath = [args objectAtIndex:index + 1];
            }
        }

        if ([args containsObject:@"-c"]) {
            NSUInteger index = [args indexOfObject:@"-c"];
            if ((index + 1) < [args count]) { 
                certSuffix = [args objectAtIndex:index + 1];
            }
        }

        if ([args containsObject:@"-o"]) {
            NSUInteger index = [args indexOfObject:@"-o"];
            if ((index + 1) < [args count]) { 
                outputPath = [args objectAtIndex:index + 1];
            }
        }
        
        if ([args containsObject:@"-v"] && ![args containsObject:@"-p"]) {
            NSUInteger index = [args indexOfObject:@"-v"];
            if ((index + 1) < [args count]) {
                verifyPath = [args objectAtIndex:index + 1];
            }
        }
        
        if (!passPath && !verifyPath) {
            PSPrintLine(@"usage:\tsignpass -p <rawpass> [-o <path>] [-c <certSuffix>]");
            PSPrintLine(@"\tsignpass -v <signedpass>");
            PSPrintLine(@"\n\t -p Sign and zip a raw pass directory");
            PSPrintLine(@"\t -v Unzip and verify a signed pass's signature and manifest. This DOES NOT validate pass content.");
        } else {
            
            if (passPath) {
                NSURL *outputURL;
                
                if (outputPath == nil) {
                    outputPath = [[passPath stringByDeletingPathExtension] stringByAppendingPathExtension:@"pkpass"];
                }
                
                outputURL = [NSURL fileURLWithPath:outputPath];
                NSURL *passURL = [NSURL fileURLWithPath:passPath];
                [PassSigner signPassWithURL:passURL certSuffix:certSuffix outputURL:outputURL zip:YES];
            } else if (verifyPath) {
                NSURL *verifyURL = [NSURL fileURLWithPath:verifyPath];
                [PassSigner verifyPassSignatureWithURL:verifyURL];
            }
        }
    }
    return 0;
}

