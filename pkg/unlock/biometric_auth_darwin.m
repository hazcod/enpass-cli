//go:build darwin
// +build darwin

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

static char *enpasscli_copy_error(NSString *message) {
	if (message == nil) {
		message = @"unknown error";
	}
	return strdup([message UTF8String]);
}

int enpasscli_authenticate_biometric(const char *reasonChars, char **errorOut) {
	@autoreleasepool {
		if (errorOut != NULL) {
			*errorOut = NULL;
		}

		NSString *reason = @"Unlock Enpass vault with Touch ID";
		if (reasonChars != NULL && reasonChars[0] != '\0') {
			reason = [NSString stringWithUTF8String:reasonChars];
		}

		LAContext *context = [[LAContext alloc] init];
		NSError *canEvaluateError = nil;
		LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
		if (![context canEvaluatePolicy:policy error:&canEvaluateError]) {
			if (errorOut != NULL) {
				*errorOut = enpasscli_copy_error([canEvaluateError localizedDescription]);
			}
			return 0;
		}

		dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
		__block BOOL authenticated = NO;
		__block NSString *authError = nil;

		[context evaluatePolicy:policy localizedReason:reason reply:^(BOOL success, NSError *error) {
			authenticated = success;
			if (!success) {
				authError = [[error localizedDescription] copy];
			}
			dispatch_semaphore_signal(semaphore);
		}];

		dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
		if (!authenticated) {
			if (errorOut != NULL) {
				*errorOut = enpasscli_copy_error(authError);
			}
			return 0;
		}

		return 1;
	}
}
