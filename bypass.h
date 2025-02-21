#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>

namespace bypass
{
    struct hook_info
    {
        void *ptr_addr;
        void *hook_addr;
        void *orig_addr;
        bool is_swap_hook;
    };

    std::vector<hook_info *> hooked_funcs;

    #define LOGD(fmt, ...) std::printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
    #define LOGE(fmt, ...) std::fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

    hook_info *find_hook_by_address(void *addr)
    {
        for (auto *info : hooked_funcs)
        {
            if (info->ptr_addr == addr || info->hook_addr == addr || info->orig_addr == addr)
            {
                return info;
            }
        }
        return nullptr;
    }

    bool is_hook_registered(void *addr)
    {
        return find_hook_by_address(addr) != nullptr;
    }

    void remove_hook(void *addr)
    {
        for (auto it = hooked_funcs.begin(); it != hooked_funcs.end(); ++it)
        {
            if ((*it)->ptr_addr == addr)
            {
                *((void **)(*it)->ptr_addr) = (*it)->orig_addr;
                _g_cheat.load()->_allocator->free(*it);
                hooked_funcs.erase(it);
                LOGD("Hook removed at address: %p", addr);
                return;
            }
        }
        LOGE("Hook not found at address: %p", addr);
    }

    template<class h, class o>
    void icall_hook(void *delegate_addr, const char *method_name, h hook, o orig, const char *dll = "libunity")
    {
        if (!delegate_addr)
        {
            LOGE("Delegate address is null!");
            return;
        }

        if (is_hook_registered(delegate_addr))
        {
            LOGE("Hook already registered at address: %p", delegate_addr);
            return;
        }

        hook_info *info = _g_cheat.load()->_allocator->calloc<hook_info>();
        if (!info)
        {
            LOGE("Failed to allocate memory for hook info!");
            return;
        }

        info->ptr_addr  = delegate_addr;
        info->hook_addr = (void *) hook;
        info->is_swap_hook = false;

        auto *_icall = new il2cpp::icall(dll, method_name);
        if (!_icall)
        {
            LOGE("Failed to create icall object!");
            _g_cheat.load()->_allocator->free(info);
            return;
        }

        void *orig_addr;
        if (!strcmp(dll, "libunity"))
        {
            orig_addr = _icall->resolve_icall_unity();
        }
        else
        {
            orig_addr = _icall->resolve_icall();
        }

        if (!orig_addr)
        {
            LOGE("Failed to resolve icall for method: %s", method_name);
            _g_cheat.load()->_allocator->free(info);
            delete _icall;
            return;
        }

        if (orig) { * (void **) orig = orig_addr; }

        info->orig_addr = orig_addr;
        hooked_funcs.push_back(info);

        * (void **) delegate_addr = (void *) hook;
        LOGD("Hook installed at address: %p, original address: %p", delegate_addr, orig_addr);
    }

    template<class h, class o>
    void swap_ptr(void *addr, h hk, o orig)
    {
        if (!addr)
        {
            LOGE("Address is null!");
            return;
        }

        if (is_hook_registered(addr))
        {
            LOGE("Hook already registered at address: %p", addr);
            return;
        }

        hook_info *info = _g_cheat.load()->_allocator->calloc<hook_info>();
        if (!info)
        {
            LOGE("Failed to allocate memory for hook info!");
            return;
        }

        info->ptr_addr  = addr;
        info->hook_addr = (void *) hk;
        info->orig_addr = * (void **) addr;
        info->is_swap_hook = true;

        hooked_funcs.push_back(info);

        menu_includes::hook(addr, (void *) hk, (void **) orig);
        LOGD("Pointer swapped at address: %p, original address: %p", addr, info->orig_addr);
    }

    void *(*orig_shared_getrr)(const char *id, const char *report_arg);
    void *hk_shared_getrr(const char *id, const char *report_arg)
    {
        LOGD("reparg: %s", report_arg);

        for (auto *info : hooked_funcs)
        {
            if (info->is_swap_hook)
            {
                menu_includes::hook(info->ptr_addr, info->orig_addr, nullptr);
            }
            else
            {
                * (void **) info->ptr_addr = info->orig_addr;
            }

            LOGD("Restored original address for hook: %p (swap: %d)", info->ptr_addr, info->is_swap_hook);
        }
        void *result = orig_shared_getrr(id, report_arg);
        for (auto *info : hooked_funcs)
        {
            if (info->is_swap_hook)
            {
                menu_includes::hook(info->ptr_addr, info->hook_addr, nullptr);
            }
            else
            {
                * (void **) info->ptr_addr = info->hook_addr;
            }

            LOGD("Restored hook address for hook: %p (swap: %d)", info->ptr_addr, info->is_swap_hook);
        }

        return result;
    }

    void init(plutonium_t &cheat)
    {
        void *getrr_delegate = (void *) (cheat._il2cpp->address() + 0x51186B8);
        if (!getrr_delegate)
        {
            LOGE("Failed to resolve getrr delegate address!");
            return;
        }

        icall_hook(getrr_delegate, "_Unwind_GetRR", hk_shared_getrr, &orig_shared_getrr, "libshared");
        LOGD("Bypass initialized!");
    }
}