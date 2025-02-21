#include <iostream>
#include <cstring>
#include <cstdint>

#define CHECK_PTR(ptr) ((ptr) != nullptr && (ptr) != " ")
#define SPOOF_VALUE ".._."

struct SpoofData {
    const char* argspoof;
    const char* noncespoof;
};

class Spoofer {
public:
    Spoofer(const char* a, const char* n) : arg(a), nonce(n) {}

    void* execute() {
        if (isValid(arg, nonce)) {
            SpoofData data = {SPOOF_VALUE, SPOOF_VALUE};
            spoofMemory(reinterpret_cast<uint64_t>(arg), data.argspoof);
            spoofMemory(reinterpret_cast<uint64_t>(nonce), data.noncespoof);
            std::cout << "Spoofing successful!" << std::endl;
            return reinterpret_cast<void*>(0x1);
        } else {
            std::cerr << "Invalid arguments for spoofing!" << std::endl;
            return nullptr;
        }
    }

private:
    const char* arg;
    const char* nonce;

    bool isValid(const char* a, const char* n) {
        return CHECK_PTR(a) && CHECK_PTR(n) && (n != a);
    }

    void spoofMemory(uint64_t address, const char* value) {
        std::memcpy(reinterpret_cast<void*>(address), value, std::strlen(value) + 1);
        std::cout << "Spoofed memory at address: " << std::hex << address << " with value: " << value << std::endl;
    }
};
void* orig_getrr(const char* arg, const char* nonce) {
    std::cout << "Original getrr called with arg: " << arg << ", nonce: " << nonce << std::endl;
    return nullptr;
}
void* getrr(const char* arg, const char* nonce) {
    std::cout << "Intercepted getrr called with arg: " << arg << ", nonce: " << nonce << std::endl;
    Spoofer spoofer(arg, nonce);
    void* result = spoofer.execute();
    if (result) {
        return result;
    } else {
        return orig_getrr(arg, nonce);
    }
}

void* (*trampoline_getrr)(const char*, const char*) = nullptr;

void initializeTrampoline() {
    trampoline_getrr = reinterpret_cast<void*(*)(const char*, const char*)>(libshared + 0x7B183C);
    std::cout << "Trampoline initialized!" << std::endl;
}

int main() {
    initializeTrampoline();

    const char* arg = "valid_arg";
    const char* nonce = "valid_nonce";

    void* result = getrr(arg, nonce);
    if (result) {
        std::cout << "Spoofing successful!" << std::endl;
    } else {
        std::cerr << "Spoofing failed!" << std::endl;
    }

    return 0;
}