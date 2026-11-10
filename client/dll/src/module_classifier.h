#ifndef NINJAYE_MODULE_CLASSIFIER_H
#define NINJAYE_MODULE_CLASSIFIER_H

#include <string>

namespace ninjaye
{
struct module_trust
{
    bool verified = false;
    int result_code = 0;
    std::string signer;
};

module_trust classify_module(const std::string& path);
}

#endif
