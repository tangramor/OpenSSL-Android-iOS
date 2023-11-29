//
//  ViewController.m
//  TestIosOpenssl
//
//  Created by 王俊华 on 2023/11/28.
//

#import "ViewController.h"
#import "Verifier.hpp"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *Text;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    Verifier verifier = Verifier();
    bool verified = verifier.verifyFile();
    _Text.text = verified ? @"File Verified Successfully" : @"File Verify Failed";
}


@end
