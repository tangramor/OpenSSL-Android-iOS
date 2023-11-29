//
//  main.cpp
//  TestOpenssl
//
//  Created by 王俊华 on 2023/11/28.
//

#include "Verifier.hpp"

int main(int argc, const char * argv[]) {
    
    Verifier *verifier = new Verifier();

    return verifier->verifyFile() ? 0 : 1;
}
