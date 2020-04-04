/*
 * This file is part of open-snell.

 * open-snell is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * open-snell is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with open-snell.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <map>
#include <set>
#include <fstream>

#include <spdlog/spdlog.h>

#include "ini.hh"

class INIImpl : public INI {
public:

    INIImpl() = default;
    ~INIImpl() = default;

    std::string Get(std::string_view section, std::string_view key, std::string_view def) const override {
        auto real_key = MakeKey(section, key);
        auto pos = items_.find(real_key);
        if (pos == items_.end()) {
            return std::string{def};
        }
        return pos->second;
    }

    bool Exists(std::string_view section, std::string_view key) const override {
        auto real_key = MakeKey(section, key);
        auto pos = items_.find(real_key);
        return pos != items_.end();
    }

    bool Parse(std::string_view filename);

private:
    static std::string MakeKey(std::string_view section, std::string_view key) {
        if (section.empty()) {
            return std::string{key};
        }
        return std::string{section} + "." + std::string{key};
    }

    std::set<std::string> sections_;
    std::map<std::string, std::string> items_;
};

void Strip(std::string &s) {
    s.erase(0, s.find_first_not_of(" \t"));
    s.erase(s.find_last_not_of(" \t") + 1);
}

bool INIImpl::Parse(std::string_view filename) {
    std::ifstream ifs{filename};
    std::string line;

    if (!ifs) {
        return false;
    }

    bool done = true;
    std::string section;
    int lineno = 0;
    while (std::getline(ifs, line)) {
        ++lineno;
        Strip(line);
        if (line.empty()) {
            continue;
        }
        if (line[0] == ';' || line[0] == '#') {
            continue;
        }

        if (line[0] == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            sections_.insert(section);
            SPDLOG_TRACE("ini new section {}", section);
            continue;
        }

        auto pos = line.find_first_of("=");
        if (pos == std::string::npos) {
            done = false;
            SPDLOG_ERROR("configuration file parse error at line {}: {}", lineno, line);
            break;
        }
        auto key = line.substr(0, pos);
        auto value = line.substr(pos + 1);
        Strip(key);
        Strip(value);

        items_[MakeKey(section, key)] = std::move(value);
    }
    return done;
}

std::shared_ptr<INI> INI::FromFile(std::string_view filename) {
    auto r = std::make_shared<INIImpl>();
    if (r->Parse(filename)) {
        return r;
    }
    return nullptr;
}

