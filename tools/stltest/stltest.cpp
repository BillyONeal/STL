// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "stljobs.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <limits.h>
#include <memory>
#include <mutex>
#include <optional>
#include <re2/re2.h>
#include <shared_mutex>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std;

// The following block of constants are intended to be convenient to edit by hand:

struct compiler {
    const char* name;
    const wchar_t* command;
    wstring_view flagsPrefix;
    bool compileOnly = false;
};

constexpr array<compiler, 4> compilers_table = {{
    {"c1xx", L"cl.exe",
        L"/nologo /c /W4 /w14061 /w14242 /w14582 /w14583 /w14587 /w14588 /w14265 /w14365 /w14749 /w14841 /w14842 "
        L"/w15038 /sdl /WX /Zc:strictStrings /D_ENABLE_STL_INTERNAL_CHECK /D_ENFORCE_FACET_SPECIALIZATIONS=1"},
    {"clang", L"clang-cl.exe",
        L"/nologo /c /W4 /w14061 /w14242 /w14582 /w14583 /w14587 /w14588 /w14265 /w14365 /w14749 /w14841 /w14842 "
        L"/w15038 /sdl /WX /Zc:strictStrings /D_ENABLE_STL_INTERNAL_CHECK /D_ENFORCE_FACET_SPECIALIZATIONS=1 /EHsc"},
    {"edg", L"cl.exe",
        L"/BE /nologo /c /W4 /w14061 /w14242 /w14582 /w14583 /w14587 /w14588 /w14265 /w14365 /w14749 /w14841 /w14842 "
        L"/w15038 /sdl /WX /Zc:strictStrings /D_ENABLE_STL_INTERNAL_CHECK /D_ENFORCE_FACET_SPECIALIZATIONS=1 /EHsc",
        true},
    {"cuda", L"nvcc.exe",
        L"/nologo /c /W4 /w14061 /w14242 /w14582 /w14583 /w14587 /w14588 /w14265 /w14365 /w14749 /w14841 /w14842 "
        L"/w15038 /sdl /WX /Zc:strictStrings /D_ENABLE_STL_INTERNAL_CHECK /D_ENFORCE_FACET_SPECIALIZATIONS=1",
        true},
}};

struct configuration {
    string_view compiler;
    wstring_view flags;
    unsigned int language  = 20;
    bool language_required = false;
};

constexpr array<configuration, 30> configurations_table = {{
    {"c1xx", L"/EHsc /MD /D_ITERATOR_DEBUG_LEVEL=0 /Od", 14},
    {"c1xx", L"/EHsc /MD /D_ITERATOR_DEBUG_LEVEL=0 /D_HAS_IF_CONSTEXPR=0 /Od", 14, true},
    {"c1xx", L"/EHsc /MD /D_ITERATOR_DEBUG_LEVEL=0 /Od", 17},
    {"c1xx", L"/EHsc /MD /D_ITERATOR_DEBUG_LEVEL=1 /Od"},
    {"c1xx", L"/EHsc /MD /D_ITERATOR_DEBUG_LEVEL=0 /Zc:char8_t- /Od"},
    {"c1xx", L"/EHsc /MDd /D_ITERATOR_DEBUG_LEVEL=0 /Od"},
    {"c1xx", L"/EHsc /MDd /D_ITERATOR_DEBUG_LEVEL=1 /Od"},
    {"c1xx", L"/EHsc /MDd /D_ITERATOR_DEBUG_LEVEL=2 /fp:except /Od", 14},
    {"c1xx", L"/EHsc /MDd /D_ITERATOR_DEBUG_LEVEL=2 /D_HAS_IF_CONSTEXPR=0 /Od", 14, true},
    {"c1xx", L"/EHsc /MDd /D_ITERATOR_DEBUG_LEVEL=2 /permissive- /Od", 17},
    {"c1xx", L"/EHsc /MT /D_ITERATOR_DEBUG_LEVEL=0 /Od"},
    {"c1xx", L"/EHsc /MT /D_ITERATOR_DEBUG_LEVEL=0 /analyze:only"},
    {"c1xx", L"/EHsc /MT /D_ITERATOR_DEBUG_LEVEL=1 /Od"},
    {"c1xx", L"/EHsc /MTd /D_ITERATOR_DEBUG_LEVEL=0 /fp:strict /Od"},
    {"c1xx", L"/EHsc /MTd /D_ITERATOR_DEBUG_LEVEL=1 /Od"},
    {"c1xx", L"/EHsc /MTd /D_ITERATOR_DEBUG_LEVEL=2 /Od"},
    {"c1xx", L"/EHsc /MTd /D_ITERATOR_DEBUG_LEVEL=2 /analyze:only /Od"},
    {"c1xx", L"/Za /EHsc /MD /permissive- /Od"},
    {"c1xx", L"/Za /EHsc /MDd /permissive- /Od"},
    {"c1xx", L"/clr /MD /Od", 17},
    {"c1xx", L"/clr /MDd /Od", 17},
    {"c1xx", L"/clr:pure /MD /Od", 14, true},
    {"c1xx", L"/clr:pure /MDd /Od", 14, true},
    {"edg", L"/MD /Od", 14},
    {"edg", L"/MDd /permissive- /Od", 17},
    {"edg", L"/MTd /permissive- /Od"},
    {"clang", L"-fno-ms-compatibility -fno-delayed-template-parsing /MD /Od", 14},
    {"clang", L"-fno-ms-compatibility -fno-delayed-template-parsing /MDd /Od", 17},
    {"clang", L"-fno-ms-compatibility -fno-delayed-template-parsing /MTd /fp:strict /Od"},
    {"c1xx", L"/EHsc /MT /O2 /GL /analyze"},
}};

struct feature_set {
    string_view name;
    wstring_view skipFlags;
};

constexpr array<feature_set, 3> feature_sets_table = {{
    {"default", L"/O2"},
    {"windows", L"/Za /O2"},
    {"fast", L"/Od /analyze:only"},
}};

// End convenient to edit by hand constants.

wstring search_path(const wchar_t* const lookFor) {
    wstring result;
    result.resize(MAX_PATH);
    LPWSTR unused;
    bool fits = false;
    while (!fits) {
        const auto searchLength = SearchPathW(nullptr, lookFor, nullptr, MAX_PATH, result.data(), &unused);
        if (searchLength == 0) {
            api_failure("SearchPathW");
        }

        fits = searchLength <= result.size();
        result.resize(searchLength);
    }

    return result;
}

struct hydrated_compiler {
    string_view name;
    wstring command;
    wstring_view flagsPrefix;
    bool compileOnly;
};

struct extracted_source_file {
    unsigned int language = 20;
    vector<string> requiredFeatures;
    bool compileOnly = false;
};

struct hydrated_configurations {
    vector<hydrated_compiler> compilers;

    template <size_t CompilerCount>
    explicit hydrated_configurations(const array<compiler, CompilerCount>& compilersRaw) {
        for (auto&& compiler : compilersRaw) {
            wstring compilerPath;
            try {
                compilerPath = search_path(compiler.command);
            } catch (const api_exception& api) {
                fprintf(stderr,
                    "Warning: the compiler \"%s\" was not found (SearchPathW GetLastError was 0x%08X); configurations "
                    "targeting it will be skipped.\n",
                    compiler.name, api.lastError);
                continue;
            }

            compilers.push_back({compiler.name, move(compilerPath), compiler.flagsPrefix, compiler.compileOnly});
        }
    }
};
//
// struct test_input {
//    filesystem::path root;
//    bool isDirectory;
//    optional<output_collecting_handle> contents;
//
//    explicit test_input(const filesystem::path& root_, bool isDirectory_) : root(root_), isDirectory(isDirectory_) {
//        if (!isDirectory) {
//            contents.emplace(create_file(root.c_str(), FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ, nullptr,
//                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, HANDLE{}),
//                [this](PTP_CALLBACK_INSTANCE env, string& s) {
//                    printf("%ls was %zu bytes long.\n", root.c_str(), s.size());
//                });
//        }
//    }
//};
//
// struct test_configuration {
//    const test_input* input;
//    const hydrated_compiler* compiler;
//};

extern "C" int wmain(int argc, const wchar_t* argv[]) {
    // try {
    vector<filesystem::path> roots;
    for (int thisRoot = 1; thisRoot < argc; ++thisRoot) {
        roots.emplace_back(argv[thisRoot]);
    }

    if (roots.empty()) {
        roots.emplace_back(filesystem::current_path());
    }

    hydrated_configurations hydrated{compilers_table};

    vector<polymorphic_sender<file_contents_result>> inputs;
    for (const filesystem::path& root : roots) {
        for (const filesystem::directory_entry& p : filesystem::directory_iterator(root)) {
            // bool isDirectory;
            switch (p.status().type()) {
            case filesystem::file_type::directory:
                // isDirectory = true; TODO
                // break;
                continue;
            case filesystem::file_type::regular:
                // isDirectory = false;
                break;
            default:
                continue;
            }

            inputs.emplace_back(read_file_contents_async(p.path()));
        }
    }

    auto joined = then(when_all<file_contents_result>(move(inputs)),
        [](vector<variant<monostate, exception_ptr, file_contents_result>>&& results) {
            string totalOutput;
            for (auto&& result : results) {
                auto& successCase = get<2>(result);
                totalOutput.append(successCase.name.u8string());
                totalOutput.append(" contained:\n");
                totalOutput.append(successCase.contents);
                totalOutput.push_back('\n');
            }

            return totalOutput;
        });

    auto total = sync_wait<string>(std::move(joined));
    puts(total.c_str());

    // std::vector<test_configuration> configs;
    //{
    //    shared_mutex mtx;
    //    for_each(execution::par, inputs.begin(), inputs.end(), [&](const test_input& i) {
    //        // TODO read the file and decide what configurations to use
    //        // For each test:
    //        // * For each configuration
    //        //   Apply min-language-mode language transform
    //        //   Apply feature transforms
    //        //   Apply compile-only transform
    //        // * Remove incompatible configurations
    //        // * Remove identical configurations
    //        vector<test_configuration> thisConfig;
    //        for (const auto& config : hydrated.compilers) {
    //            thisConfig.push_back({&i, &config});
    //        }

    //        lock_guard lck(mtx);
    //        configs.insert(configs.end(), thisConfig.begin(), thisConfig.end());
    //    });
    //}

    TerminateProcess(GetCurrentProcess(), 0);
    //} catch (filesystem::filesystem_error& err) {
    //    fputs(err.what(), stderr);
    //    abort();
    //} catch (const api_exception& api) {
    //    api.give_up();
    //}
}
