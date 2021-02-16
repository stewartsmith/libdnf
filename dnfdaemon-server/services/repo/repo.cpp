/*
Copyright (C) 2020 Red Hat, Inc.

This file is part of dnfdaemon-server: https://github.com/rpm-software-management/libdnf/

Dnfdaemon-server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Dnfdaemon-server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with dnfdaemon-server.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "repo.hpp"

#include "dnfdaemon-server/dbus.hpp"
#include "dnfdaemon-server/utils.hpp"

#include <fmt/format.h>
#include <libdnf/rpm/package_set.hpp>
#include <libdnf/rpm/repo.hpp>
#include <libdnf/rpm/solv_query.hpp>
#include <sdbus-c++/sdbus-c++.h>

#include <chrono>
#include <iostream>
#include <string>

void Repo::dbus_register() {
    auto dbus_object = session.get_dbus_object();
    dbus_object->registerMethod(
        dnfdaemon::INTERFACE_REPO, "list", "a{sv}", "aa{sv}", [this](sdbus::MethodCall call) -> void {
            this->list(call);
        });
}

uint64_t repo_size(libdnf::rpm::SolvSack & sack, const libdnf::WeakPtr<libdnf::rpm::Repo, false> & repo) {
    uint64_t size = 0;
    libdnf::rpm::SolvQuery query(&sack);
    std::vector<std::string> reponames = {repo->get_id()};
    query.ifilter_repoid(libdnf::sack::QueryCmp::EQ, reponames);
    for (auto pkg : query) {
        size += pkg.get_download_size();
    }
    return size;
}

bool keyval_repo_compare(const dnfdaemon::KeyValueMap & first, const dnfdaemon::KeyValueMap & second) {
    return key_value_map_get<std::string>(first, "id") < key_value_map_get<std::string>(second, "id");
}

void Repo::list(sdbus::MethodCall call) {
    dnfdaemon::KeyValueMap options;
    call >> options;
    auto worker = std::thread([this, options = std::move(options), call = std::move(call)]() {
        try {
            // read options from dbus call
            std::string enable_disable = key_value_map_get<std::string>(options, "enable_disable", "enabled");
            std::vector<std::string> default_patterns{};
            std::vector<std::string> patterns =
                key_value_map_get<std::vector<std::string>>(options, "patterns", std::move(default_patterns));
            std::string command = key_value_map_get<std::string>(options, "command", "repolist");

            // repoinfo command needs repositories loaded into sack
            // TODO(mblaha): check that repos are loaded

            // prepare repository query filtered by options
            auto base = session.get_base();
            auto & solv_sack = base->get_rpm_solv_sack();
            auto & rpm_repo_sack = base->get_rpm_repo_sack();
            auto repos_query = rpm_repo_sack.new_query();

            if (enable_disable == "enabled") {
                repos_query.ifilter_enabled(true);
            } else if (enable_disable == "disabled") {
                repos_query.ifilter_enabled(false);
            }

            if (patterns.size() > 0) {
                auto query_names = repos_query;
                repos_query.ifilter_id(libdnf::sack::QueryCmp::IGLOB, patterns);
                repos_query |= query_names.ifilter_name(libdnf::sack::QueryCmp::IGLOB, patterns);
            }

            // create reply from the query
            dnfdaemon::KeyValueMapList out_repositories;
            for (auto & repo : repos_query.get_data()) {
                dnfdaemon::KeyValueMap out_repo;
                out_repo.emplace(std::make_pair("id", repo->get_id()));
                out_repo.emplace(std::make_pair("name", repo->get_config().name().get_value()));
                out_repo.emplace(std::make_pair("enabled", repo->is_enabled()));
                // TODO(mblaha): add all other repository attributes
                if (command == "repoinfo") {
                    out_repo.emplace(std::make_pair("repo_size", repo_size(solv_sack, repo)));
                }
                out_repositories.push_back(std::move(out_repo));
            }

            std::sort(out_repositories.begin(), out_repositories.end(), keyval_repo_compare);
            auto reply = call.createReply();
            reply << out_repositories;
            reply.send();
        } catch (std::exception & ex) {
            DNFDAEMON_ERROR_REPLY(call, ex);
        }
        session.get_threads_manager().current_thread_finished();
    });
    session.get_threads_manager().register_thread(std::move(worker));
}