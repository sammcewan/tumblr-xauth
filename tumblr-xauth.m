// tumblr-xauth.m
//
// Tumblr modifications by Sam McEwan on 23/07/2012
//
// Created by Eric Johnson on 08/27/2010.
// Copyright 2010 Eric Johnson. All rights reserved.
//
// Permission is given to use this source code file, free of charge, in any
// project, commercial or otherwise, entirely at your risk, with the condition
// that any redistribution (in part or whole) of source code must retain
// this copyright and permission notice. Attribution in compiled projects is
// appreciated but not required.

#import <Foundation/Foundation.h>
#import "TumblrXAuth.h"

//update these:
#define CONSUMER_KEY @""
#define CONSUMER_SECRET @""
#define TUMBLR_USERNAME @""
#define TUMBLR_PASSWORD @""

@interface TestTumblrXAuth : NSObject <TumblrXAuthDelegate>
+ (void) testTumblrXAuth;
@end

@implementation TestTumblrXAuth

static TumblrXAuth * tumblrXAuth = nil;

+ (void) testTumblrXAuth
{
  self = [[TestTumblrXAuth alloc] init];
  [tumblrXAuth release];
  tumblrXAuth = [[TumblrXAuth alloc] init];

  tumblrXAuth.consumerKey = CONSUMER_KEY;
  tumblrXAuth.consumerSecret = CONSUMER_SECRET;
  tumblrXAuth.username = TUMBLR_USERNAME;
  tumblrXAuth.password = TUMBLR_PASSWORD;
  tumblrXAuth.delegate = self;
  
  [tumblrXAuth authorize];
}

- (void) tumblrXAuthDidAuthorize:(TumblrXAuth *)tumblrXAuth
{
  NSLog(@"authorization successful");
    [tumblrXAuth info];
}

- (void) tumblrXAuthAuthorizationDidFail:(TumblrXAuth *)tumblrXAuth
{
  NSLog(@"authorization failed");
}

- (void) tumblrXAuthInfoDidFail:(TumblrXAuth *)tumblrXAuth
{
  NSLog(@"Info failed"); 

}

- (void) tumblrXAuthInfo:(TumblrXAuth *)tumblrXAuth;
{
  NSLog(@"Info successful"); 
  NSLog(@"Info: %@", tumblrXAuth.infoString);
}

@end


int main(int argc, char * argv[]) {
  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];

  [TestTumblrXAuth testTumblrXAuth];
  
  [[NSRunLoop currentRunLoop] run];
  
  [pool release];
  return 0;
}
