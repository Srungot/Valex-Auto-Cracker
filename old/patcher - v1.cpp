#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <locale>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace skc
{
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class skCrypter
	{
	public:
		__forceinline constexpr skCrypter(T* data)
		{		
			crypt(data);
		}

		__forceinline T* get()
		{
			return _storage;
		}

		__forceinline int size()
		{
			return _size;
		}

		__forceinline  char key()
		{
			return _key1;
		}

		__forceinline  T* encrypt()
		{
			if (!isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline  T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline bool isEncrypted()
		{
			return _storage[_size - 1] != 0;
		}

		__forceinline void clear()
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = 0;
			}
		}

		__forceinline operator T* ()
		{
			decrypt();

			return _storage;
		}
		
	private:
		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
			}
		}	

		T _storage[_size]{};
	};
}

#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

bool findPattern(const std::vector<uint8_t>& buf,
                 const std::vector<int>& pat,
                 size_t& outPos) {
    for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (pat[j] >= 0 && buf[i + j] != static_cast<uint8_t>(pat[j])) {
                ok = false;
                break;
            }
        }
        if (ok) { outPos = i; return true; }
    }
    return false;
}

static std::vector<size_t> findAllPatterns(const std::vector<uint8_t>& buf,
                                           const std::vector<int>& pat) {
    std::vector<size_t> hits;
    if (pat.empty() || buf.size() < pat.size()) return hits;
    for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (pat[j] >= 0 && buf[i + j] != static_cast<uint8_t>(pat[j])) {
                ok = false;
                break;
            }
        }
        if (ok) hits.push_back(i);
    }
    return hits;
}

static int32_t readRel32(const std::vector<uint8_t>& buf, size_t pos) {
    int32_t val;
    std::memcpy(&val, &buf[pos], 4);
    return val;
}
static void writeRel32(std::vector<uint8_t>& buf, size_t pos, int32_t val) {
    std::memcpy(&buf[pos], &val, 4);
}

static uint16_t rd16(const std::vector<uint8_t>& b, size_t o){ uint16_t v=0; if(o+2<=b.size()) std::memcpy(&v,&b[o],2); return v; }
static uint32_t rd32(const std::vector<uint8_t>& b, size_t o){ uint32_t v=0; if(o+4<=b.size()) std::memcpy(&v,&b[o],4); return v; }
static uint64_t rd64(const std::vector<uint8_t>& b, size_t o){ uint64_t v=0; if(o+8<=b.size()) std::memcpy(&v,&b[o],8); return v; }

struct PeSection {
    uint32_t va;
    uint32_t vsize;
    uint32_t rawPtr;
    uint32_t rawSize;
};

static bool parsePE64(const std::vector<uint8_t>& buf, uint64_t& imageBase, std::vector<PeSection>& secs) {
    if (buf.size() < 0x1000) return false;
    if (!(buf.size() >= 0x40) || buf[0] != 'M' || buf[1] != 'Z') return false;
    uint32_t e_lfanew = rd32(buf, 0x3C);
    if (e_lfanew + 0x18 > buf.size()) return false;
    if (rd32(buf, e_lfanew) != 0x00004550) return false;  
    size_t fileHdr = e_lfanew + 4;
    uint16_t numSecs = rd16(buf, fileHdr + 2);
    uint16_t optSize = rd16(buf, fileHdr + 16);
    size_t optHdr = fileHdr + 20;
    if (optHdr + optSize > buf.size()) return false;
    uint16_t magic = rd16(buf, optHdr + 0);
    if (magic != 0x20B) return false;   
    imageBase = rd64(buf, optHdr + 24);
    size_t secTable = optHdr + optSize;
    secs.clear(); secs.reserve(numSecs);
    for (uint16_t i = 0; i < numSecs; ++i) {
        size_t sh = secTable + i * 40; 
        if (sh + 40 > buf.size()) return false;
        uint32_t vsize = rd32(buf, sh + 8);
        uint32_t va     = rd32(buf, sh + 12);
        uint32_t rawSz  = rd32(buf, sh + 16);
        uint32_t rawPtr = rd32(buf, sh + 20);
        secs.push_back({va, vsize, rawPtr, rawSz});
    }
    return true;
}

static bool vaToFileOffset(uint64_t imageBase, const std::vector<PeSection>& secs, uint64_t va, size_t& fileOff) {
    if (va < imageBase) return false;
    uint64_t rva = va - imageBase;
    for (const auto& s : secs) {
        uint32_t vspan = std::max(s.vsize, s.rawSize);
        if (rva >= s.va && rva < static_cast<uint64_t>(s.va) + vspan) {
            uint64_t delta = rva - s.va;
            uint64_t off = s.rawPtr + delta;
            fileOff = static_cast<size_t>(off);
            return true;
        }
    }
    return false;
}

static bool fileOffsetToVA(uint64_t imageBase, const std::vector<PeSection>& secs, size_t fileOff, uint64_t& va) {
    for (const auto& s : secs) {
        uint32_t rawEnd = s.rawPtr + s.rawSize;
        if (fileOff >= s.rawPtr && fileOff < rawEnd) {
            uint64_t delta = static_cast<uint64_t>(fileOff - s.rawPtr);
            va = imageBase + static_cast<uint64_t>(s.va) + delta;
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    system(skCrypt("cls").decrypt());
#else
    system(skCrypt("clear").decrypt());
#endif

#ifdef _WIN32
    auto enableVT = [](){
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;
        DWORD dwMode = 0;
        if (!GetConsoleMode(hOut, &dwMode)) return;
        dwMode |= 0x0004;  
        SetConsoleMode(hOut, dwMode);
    };
    enableVT();
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::setlocale(LC_ALL, skCrypt(".UTF-8").decrypt());
#endif

    auto nowTime = [](){
        using namespace std::chrono;
        auto t = system_clock::to_time_t(system_clock::now());
        std::tm tm;
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream oss; oss << std::setfill('0') << std::setw(2) << tm.tm_hour << ":"
                                    << std::setw(2) << tm.tm_min << ":" << std::setw(2) << tm.tm_sec;
        return oss.str();
    };

    auto XY = [&](const char* tagColor, const char* msgColor, const std::string& msg){
        std::cout << skCrypt("\x1b[90m[").decrypt() << nowTime() << skCrypt("]\x1b[0m ").decrypt()
                  << tagColor << skCrypt("[ XYLERA ]\x1b[0m ").decrypt()
                  << msgColor << msg << skCrypt("\x1b[0m\n").decrypt();
    };
    const char* COL_INFO = skCrypt("\x1b[38;5;207m").decrypt();
    const char* COL_OK   = skCrypt("\x1b[38;5;83m").decrypt();
    const char* COL_WARN = skCrypt("\x1b[38;5;214m").decrypt();
    const char* COL_ERR  = skCrypt("\x1b[38;5;203m").decrypt();
    const char* COL_MSG  = skCrypt("\x1b[37m").decrypt();
    auto XY_INFO = [&](const std::string& m){ XY(COL_INFO, COL_MSG, m); };
    auto XY_OK   = [&](const std::string& m){ XY(COL_OK,   skCrypt("\x1b[32m").decrypt(), m); };
    auto XY_WARN = [&](const std::string& m){ XY(COL_WARN, skCrypt("\x1b[33m").decrypt(), m); };
    auto XY_ERR  = [&](const std::string& m){ XY(COL_ERR,  skCrypt("\x1b[31m").decrypt(), m); };

    auto to_hex = [](unsigned long long v){ std::ostringstream oss; oss << std::hex << v; return oss.str(); };
    auto to_dec = [](unsigned long long v){ std::ostringstream oss; oss << v; return oss.str(); };

    const std::string symOK = skCrypt("OK").decrypt();
    const std::string symArrow = skCrypt("->").decrypt();

    auto getConsoleWidth = []() -> int {
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
            return csbi.srWindow.Right - csbi.srWindow.Left + 1;
        }
#endif
        return 80;  
    };
    
    auto getVisibleLength = [](const std::string& text) -> int {
        int visibleLen = 0;
        bool inEscape = false;
        for (size_t i = 0; i < text.length(); ++i) {
            if (text[i] == '\x1b' && i + 1 < text.length() && text[i + 1] == '[') {
                inEscape = true;
                ++i;    
            } else if (inEscape && text[i] == 'm') {
                inEscape = false;
            } else if (!inEscape) {
                ++visibleLen;
            }
        }
        return visibleLen;
    };    
    
    auto centerText = [&](const std::string& text) -> std::string {
        int width = getConsoleWidth();
        int visibleLen = getVisibleLength(text);
        int padding = std::max(0, (width - visibleLen) / 2);
        return std::string(std::max(0, padding), ' ') + text;
    };

    auto printBannerFancy = [&](){
        std::cout << "\n";
        std::cout << centerText(skCrypt("\x1b[38;5;207m __ __ __ __ __    _____ _____ _____ \x1b[0m").decrypt()) << "\n";
        std::cout << centerText(skCrypt("\x1b[38;5;213m|  |  |  |  |  |  |   __| __  |  _  |\x1b[0m").decrypt()) << "\n";
        std::cout << centerText(skCrypt("\x1b[38;5;219m|-   -|_   _|  |__|   __|    -|     |\x1b[0m").decrypt()) << "\n";
        std::cout << centerText(skCrypt("\x1b[38;5;225m|__|__| |_| |_____|_____|__|__|__|__|\x1b[0m").decrypt()) << "\n";
        std::cout << "\n" << centerText(skCrypt("\x1b[90mValex Patcher by \x1b[0m\x1b[38;5;207mXYLERA\x1b[0m").decrypt()) << "\n";
        std::cout << centerText(skCrypt("\x1b[90mMake it clean. Make it glow.\x1b[0m").decrypt()) << "\n\n";
    };
    auto printBannerAscii = [&](){
        std::cout << "\n";
        std::cout << centerText(skCrypt(" __ __ __ __ __    _____ _____ _____ ").decrypt()) << "\n";
        std::cout << centerText(skCrypt("|  |  |  |  |  |  |   __| __  |  _  |").decrypt()) << "\n";
        std::cout << centerText(skCrypt("|-   -|_   _|  |__|   __|    -|     |").decrypt()) << "\n";
        std::cout << centerText(skCrypt("|__|__| |_| |_____|_____|__|__|__|__|").decrypt()) << "\n\n";
        std::cout << centerText(skCrypt("[ XYLERA ] Valex Patcher").decrypt()) << "\n";
        std::cout << centerText(skCrypt("Make it clean. Make it glow.").decrypt()) << "\n\n";
    };
#ifdef _WIN32
    if (GetConsoleOutputCP() == CP_UTF8) printBannerFancy(); else printBannerAscii();
#else
    printBannerFancy();
#endif
    if (argc < 2 || !argv[1] || std::strlen(argv[1]) == 0) {
        XY_ERR(skCrypt("[!] Usage: patcher.exe <input.exe>\n").decrypt());
        return 1;
    }

    namespace fs = std::filesystem;
    fs::path inPath = fs::path(argv[1]);
    if (!fs::exists(inPath)) {
        XY_ERR(std::string(skCrypt("Error: input file does not exist -> ").decrypt()) + inPath.string());
        return 1;
    }

    std::string outName = std::string(skCrypt("patched_").decrypt()) + inPath.filename().string();
    fs::path outPath = inPath.parent_path() / outName;
    std::string inFile = inPath.string();
    std::string outFile = outPath.string();

    std::ifstream in(inFile, std::ios::binary);
    if (!in) { XY_ERR(std::string(skCrypt("Error opening ").decrypt()) + inFile); return 1; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), {});
    in.close();

    uint64_t imageBase = 0;
    std::vector<PeSection> sections;
    if (!parsePE64(buf, imageBase, sections)) {
        XY_WARN(skCrypt("PE64 parse failed; some features may not work correctly").decrypt());
    }

    std::string patternCall = skCrypt("E8 ? ? ? ? 84 C0 0F 85 87 00 00 00 48 8D 05 ? ? ? ? 48 89 84 24 20 01 00 00 48 C7 84 24 28 01 00 00 15 00 00 00").decrypt();
    std::string patternJnz  = skCrypt("0F 85 87 00 00 00 48 8D 05 ? ? ? ? 48 89 84 24 20 01 00 00 48 C7 84 24 28 01 00 00 15 00 00 00").decrypt();
    
    auto parsePattern = [](const std::string& pattern) {
        std::vector<int> result;
        std::istringstream iss(pattern);
        std::string token;
        while (iss >> token) {
            if (token == "?") {
                result.push_back(-1);
            } else {
                result.push_back(std::stoi(token, nullptr, 16));
            }
        }
        return result;
    };
    
    {
        const std::string patternVersion = skCrypt("48 8D 0D ? ? ? ? 48 89 08 48 8D 0D").decrypt();
        auto sigVersion = parsePattern(patternVersion);
        auto hitsVer = findAllPatterns(buf, sigVersion);
        if (!hitsVer.empty()) {
            size_t off = hitsVer[0];
            if (off + 7 <= buf.size()) {
                int32_t disp = readRel32(buf, off + 3);
                uint64_t instrVA = 0;
                if (!fileOffsetToVA(imageBase, sections, off, instrVA)) {
                    XY_WARN(skCrypt("Cannot map file offset to VA for version pattern").decrypt());
                } else {
                    uint64_t ripVA = instrVA + 7;
                    uint64_t targetVA = ripVA + static_cast<int64_t>(disp);
                    size_t strOff = 0;
                    if (vaToFileOffset(imageBase, sections, targetVA, strOff) && strOff < buf.size()) {
                        std::string ver;
                        for (size_t i = strOff; i < buf.size() && ver.size() < 256; ++i) {
                            uint8_t c = buf[i];
                            if (c == 0) break;
                            if (c < 0x20 || c > 0x7E) { ver.clear(); break; }
                            ver.push_back(static_cast<char>(c));
                        }
                        if (!ver.empty()) {
                            XY_OK(std::string(skCrypt("Valex version: ").decrypt()) + ver);
                        } else {
                            size_t winStart = (strOff > 128) ? (strOff - 128) : 0;
                            size_t winEnd = std::min(buf.size(), strOff + 256ULL);
                            bool found = false;
                            for (size_t i = winStart; i + 7 < winEnd; ++i) {
                                std::string s;
                                for (size_t j = i; j < winEnd && s.size() < 256; ++j) {
                                    uint8_t c = buf[j];
                                    if (c == 0) break;
                                    if (c < 0x20 || c > 0x7E) { s.clear(); break; }
                                    s.push_back(static_cast<char>(c));
                                }
                                if (!s.empty()) {
                                    std::string lower = s; std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                                    if (lower.find(skCrpyt("version").decrypt()) != std::string::npos) {
                                        XY_OK(std::string(skCrypt("Valex version (nearby): ").decrypt()) + s +
                                              std::string(skCrypt(" @0x").decrypt()) + to_hex(static_cast<unsigned long long>(i)));
                                        found = true; break;
                                    }
                                }
                            }
                            if (!found) XY_WARN(skCrypt("Version string not readable at computed offset").decrypt());
                        }
                    } else {
                        XY_WARN(skCrypt("Failed to resolve version string target to file offset").decrypt());
                    }
                }
            }
        } else {
            XY_WARN(skCrypt("Version pattern not found (48 8D 0D ?? ?? ?? ?? 48 89 08 48 8D 0D)").decrypt());
        }
    }
    
    std::vector<int> sigCall = parsePattern(patternCall);
    std::vector<int> sigJnz = parsePattern(patternJnz);

    size_t posCall = 0, posJnz = 0;
    if (!findPattern(buf, sigCall, posCall)) {
        XY_ERR(skCrypt("CALL not found").decrypt()); return 1;
    }
    if (!findPattern(buf, sigJnz, posJnz)) {
        XY_ERR(skCrypt("JNZ not found").decrypt()); return 1;
    }

    XY_INFO(std::string(skCrypt("CALL found at 0x").decrypt()) + to_hex(static_cast<unsigned long long>(posCall)));
    XY_INFO(std::string(skCrypt("JNZ found at 0x").decrypt()) + to_hex(static_cast<unsigned long long>(posJnz)));

    int32_t relJnz = readRel32(buf, posJnz + 2);
    size_t target = (posJnz + 6) + relJnz;
    XY_INFO(std::string(skCrypt("Destination of JNZ : 0x").decrypt()) + to_hex(static_cast<unsigned long long>(target)));

    buf[posCall] = 0xE9; 
    int32_t newRel = static_cast<int32_t>(target - (posCall + 5));
    writeRel32(buf, posCall + 1, newRel);
    XY_OK(std::string(skCrypt("CALL replaced by JMP to 0x").decrypt()) + to_hex(static_cast<unsigned long long>(target)));

    {
        std::string patternJnzExact = skCrpyt("0F 85 6A 19 00 00").decrypt();
        std::string patternTarget   = skCrpyt("48 8B C8 FF 15 ? ? ? ? 90 C7 44 24 28 05 00 00 00").decrypt();
        auto sigJnzExact = parsePattern(patternJnzExact);
        auto sigTarget   = parsePattern(patternTarget);
        size_t posJnzExact = 0, posTargetSeq = 0;
        bool foundJnz = findPattern(buf, sigJnzExact, posJnzExact);
        bool foundTgt = findPattern(buf, sigTarget, posTargetSeq);
        if (foundJnz && foundTgt) {
            if (posJnzExact + 6 <= buf.size()) {
                buf[posJnzExact] = 0xE9;   
                int32_t rel = static_cast<int32_t>(posTargetSeq - (posJnzExact + 5));
                writeRel32(buf, posJnzExact + 1, rel);
                buf[posJnzExact + 5] = 0x90;        
                XY_OK(std::string(skCrypt("Exact JNZ patched to JMP at 0x").decrypt()) +
                      to_hex(static_cast<unsigned long long>(posJnzExact)) +
                      std::string(" ") + symArrow + std::string(skCrypt(" target 0x").decrypt()) +
                      to_hex(static_cast<unsigned long long>(posTargetSeq)));
            } else {
                XY_WARN(skCrypt("Skipping exact JNZ patch: out of bounds").decrypt());
            }
        } else {
            if (!foundJnz) XY_WARN(skCrypt("Exact JNZ (0F 85 6A 19 00 00) not found").decrypt());
            if (!foundTgt) XY_WARN(skCrypt("Target sequence not found (48 8B C8 FF 15 ?? ?? ?? ?? 90 C7 44 24 28 05 00 00 00)").decrypt());
        }
    }

    const std::string oldUrl = skCrypt("https://1cheats.com/store/product/41-Valex-external-key-bypass-lifetime-license/").decrypt();
    const std::string newUrl = skCrypt("https://discord.gg/xylera").decrypt();

    {
        std::string patternDebugRange =
            std::string(skCrypt("66 0F 7F 44 24 30 48 8D 54 24 30 48 8B CF ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? E8 ? ? ? ? 84 C0 0F 85 40 1A 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 7B 1A 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 B6 1A 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 F1 1A 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 2C 1B 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 67 1B 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 A2 1B 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 DD 1B 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 85 18 1C 00 00 ").decrypt()) +
            std::string(skCrypt("E8 ? ? ? ? 84 C0 0F 84 53 1C 00 00 ").decrypt()) +
            std::string(skCrypt("B9 10 00 00 00 E8").decrypt());        

        auto sigBlock = parsePattern(patternDebugRange);
        size_t posBlock = 0;
        size_t debugNoppedCalls = 0, debugNoppedJmps = 0;
        if (findPattern(buf, sigBlock, posBlock)) {
            std::vector<int> tail = parsePattern(skCrypt("B9 10 00 00 00 E8").decrypt());
            size_t posTail = posBlock;
            if (!findPattern(std::vector<uint8_t>(buf.begin() + posBlock, buf.end()), tail, posTail)) {
                posTail = sigBlock.size();
            }
            size_t start = posBlock;
            size_t end = (posTail == sigBlock.size()) ? (posBlock + sigBlock.size()) : (posBlock + posTail);
            if (end > buf.size()) end = buf.size();

            size_t noppedCalls = 0, noppedJmps = 0;
            for (size_t i = start; i + 5 <= end; ++i) {
                if (buf[i] == 0xE8) {
                    for (size_t k = 0; k < 5; ++k) buf[i + k] = 0x90;
                    ++noppedCalls;
                }
            }
            for (size_t i = start; i + 8 <= end; ++i) {
                if (buf[i] == 0x84 && buf[i + 1] == 0xC0 && buf[i + 2] == 0x0F && (buf[i + 3] == 0x85 || buf[i + 3] == 0x84)) {
                    for (size_t k = 0; k < 6; ++k) buf[i + 2 + k] = 0x90;
                    ++noppedJmps;
                }
            }
            debugNoppedCalls = noppedCalls; debugNoppedJmps = noppedJmps;
            XY_OK(std::string(skCrypt("Debug block patched at 0x").decrypt()) +
                  to_hex(static_cast<unsigned long long>(start)) +
                  std::string(skCrypt(" (end 0x").decrypt()) +
                  to_hex(static_cast<unsigned long long>(end)) + ")");
            XY_INFO(std::string(skCrypt("    - NOPed calls: ").decrypt()) + to_dec(noppedCalls));
            XY_INFO(std::string(skCrypt("    - NOPed conditional jumps: ").decrypt()) + to_dec(noppedJmps));
        } else {
            XY_WARN(skCrypt("Debug block signature not found; skipping NOP pass").decrypt());
        }
    }

    size_t replacedExact = 0;
    {
        const std::vector<uint8_t> pat(oldUrl.begin(), oldUrl.end());
        for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (buf[i + j] != pat[j]) { match = false; break; }
            }
            if (match) {
                size_t k = 0;
                for (; k < newUrl.size(); ++k) buf[i + k] = static_cast<uint8_t>(newUrl[k]);
                for (; k < pat.size(); ++k) buf[i + k] = 0x20;
                ++replacedExact;
            }
        }
    }
    XY_OK(std::string(skCrypt("URL replaced occurrences: ").decrypt()) + to_dec(replacedExact));

    {
        const std::string fromStr = skCrypt("VALEX V5").decrypt();
        const std::string toStr   = skCrypt("Cracked").decrypt();
        size_t replacedCount = 0;
        const std::vector<uint8_t> pat(fromStr.begin(), fromStr.end());
        for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (buf[i + j] != pat[j]) { match = false; break; }
            }
            if (match) {
                size_t k = 0;
                for (; k < toStr.size() && k < pat.size(); ++k)
                    buf[i + k] = static_cast<uint8_t>(toStr[k]);
                for (; k < pat.size(); ++k)
                    buf[i + k] = 0x20;  
                ++replacedCount;
            }
        }
        XY_OK(std::string(skCrypt("String replaced (\"VALEX V5\" -> \"Cracked\"): ").decrypt()) + to_dec(replacedCount));
    }

    {
        const std::string patternStrRef = skCrypt("48 8D 35 ? ? ? ? 4C 8B CE 0F 14 C1 66 49 0F 7E C0").decrypt();
        auto sigStrRef = parsePattern(patternStrRef);
        auto hits = findAllPatterns(buf, sigStrRef);
        size_t replacedCount = 0;
        if (!hits.empty()) {
            size_t off = hits[0];
            if (off + 7 <= buf.size()) {
                int32_t disp = readRel32(buf, off + 3);
                uint64_t instrVA = 0;
                if (fileOffsetToVA(imageBase, sections, off, instrVA)) {
                    uint64_t ripVA = instrVA + 7;
                    uint64_t targetVA = ripVA + static_cast<int64_t>(disp);
                    size_t strOff = 0;
                    if (vaToFileOffset(imageBase, sections, targetVA, strOff) && strOff < buf.size()) {
                        size_t origLen = 0; bool okAscii = true;
                        for (size_t i = strOff; i < buf.size() && origLen < 256; ++i) {
                            uint8_t c = buf[i];
                            if (c == 0) break;
                            if (c < 0x20 || c > 0x7E) { okAscii = false; break; }
                            ++origLen;
                        }
                        if (okAscii && origLen > 0) {
                            const std::string newStr = skCrypt("Valex cracked by xylera").decrypt();
                            size_t writeLen = std::min(origLen, newStr.size());
                            for (size_t k = 0; k < writeLen; ++k) buf[strOff + k] = static_cast<uint8_t>(newStr[k]);
                            for (size_t k = writeLen; k < origLen; ++k) buf[strOff + k] = 0x20;    
                            ++replacedCount;
                            bool truncated = newStr.size() > origLen;
                            XY_OK(std::string(skCrypt("Pattern string replaced at 0x").decrypt()) + to_hex(static_cast<unsigned long long>(strOff)) +
                                  (truncated ? std::string(" (truncated)") : std::string("")));
                        } else {
                            XY_WARN(skCrypt("Targeted string is not a valid ASCII or length is 0").decrypt());
                        }
                    } else {
                        XY_WARN(skCrypt("Could not resolve referenced string file offset for pattern").decrypt());
                    }
                } else {
                    XY_WARN(skCrypt("Could not map LEA file offset to VA for pattern").decrypt());
                }
            }
        } else {
            XY_WARN(skCrypt("String reference pattern not found (48 8D 35 ?? ?? ?? ?? 4C 8B CE 0F 14 C1 66 49 0F 7E C0)").decrypt());
        }
    }

    const std::vector<std::string> neutralizeTargets = {
        skCrypt("https://discord.gg/Valex").decrypt(),
        skCrypt("https://extkey.Valex.io/").decrypt(),
    };
    size_t neutralizedCount = 0;
    for (const auto &needle : neutralizeTargets) {
        const std::vector<uint8_t> pat(needle.begin(), needle.end());
        for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (buf[i + j] != pat[j]) { match = false; break; }
            }
            if (match) {
                for (size_t j = 0; j < pat.size(); ++j) buf[i + j] = 0x20;
                ++neutralizedCount;
            }
        }
    }
    XY_OK(std::string(skCrypt("URLs neutralized: ").decrypt()) + to_dec(neutralizedCount));

    const std::vector<int> PatternAVMADB_JNZ = {0x84, 0xC0, 0x0F, 0x85, -1, -1, 0x00, 0x00};
    const std::vector<int> PatternAVMADB_JZ  = {0x84, 0xC0, 0x0F, 0x84, -1, -1, 0x00, 0x00};

    auto hitsJNZ = findAllPatterns(buf, PatternAVMADB_JNZ);
    auto hitsJZ  = findAllPatterns(buf, PatternAVMADB_JZ);
    
    std::ofstream out(outFile, std::ios::binary);
    if (!out) {
        XY_ERR(std::string(skCrypt("Error creating output file -> ").decrypt()) + outFile);
        return 1;
    }
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    out.close();
    XY_OK(std::string(skCrypt("[").decrypt()) + symOK +
          std::string(skCrypt("] Patch completed ").decrypt()) +
          symArrow + std::string(skCrypt(" ").decrypt()) + outFile);
    
    std::cout << "\n" << centerText(skCrypt("\x1b[90mPress Enter to exit...\x1b[0m").decrypt());
    std::cin.get();

    return 0;
}