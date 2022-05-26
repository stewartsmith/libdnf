/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/


#ifndef DNF5_COMMANDS_BUILD_DEP_BUILD_DEP_HPP
#define DNF5_COMMANDS_BUILD_DEP_BUILD_DEP_HPP


#include <libdnf-cli/session.hpp>
#include <libdnf/base/goal.hpp>
#include <libdnf/conf/option_bool.hpp>

#include <memory>
#include <vector>


namespace dnf5 {


class BuildDepCommand : public libdnf::cli::session::Command {
public:
    explicit BuildDepCommand(Command & parent);
    void run() override;

private:
    void parse_builddep_specs(int specs_count, const char * const specs[]);
    bool add_from_spec_file(
        std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const char * spec_file_name);
    bool add_from_srpm_file(
        std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const char * srpm_file_name);
    bool add_from_pkg(
        std::set<std::string> & install_specs, std::set<std::string> & conflicts_specs, const std::string & pkg_spec);

    std::vector<std::string> pkg_specs{};
    std::vector<std::string> spec_file_paths{};
    std::vector<std::string> srpm_file_paths{};
    libdnf::OptionBool skip_unavailable_option{false};
    std::vector<std::pair<std::string, std::string>> rpm_macros{};
};


}  // namespace dnf5


#endif  // DNF5_COMMANDS_BUILD_DEP_BUILD_DEP_HPP
