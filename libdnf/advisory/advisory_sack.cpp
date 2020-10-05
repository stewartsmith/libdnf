/*
Copyright (C) 2021 Red Hat, Inc.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "libdnf/advisory/advisory_sack.hpp"

#include "libdnf/rpm/solv_sack_impl.hpp"

#include <solv/dataiterator.h>

namespace libdnf::advisory {

AdvisorySack::AdvisorySack(libdnf::Base & base) : data_map(0), base(&base) {}

AdvisorySack::~AdvisorySack() = default;

AdvisoryQuery AdvisorySack::new_query() {
    auto & solv_sack = base->get_rpm_solv_sack();

    if (cached_solvables_size != solv_sack.p_impl->get_nsolvables()) {
        load_advisories_from_solvsack();
    }

    return AdvisoryQuery(this);
};

void AdvisorySack::load_advisories_from_solvsack() {
    auto & solv_sack = base->get_rpm_solv_sack();
    Pool * pool = solv_sack.p_impl->get_pool();

    data_map = libdnf::rpm::solv::SolvMap(pool->nsolvables);

    Dataiterator di;

    dataiterator_init(&di, pool, 0, 0, 0, 0, 0);

    // - We want only advisories that have at least one package in them.
    // - Advisories have their own Ids but advisory packages don't.
    // - Keyname UPDATE_COLLECTION refers to packages (name, evr, arch) in advisories,
    //   it is misnamed and should be rather called UPDATE_PACKAGE.
    //
    // This loop finds the first package in an advisory, adds the advisory
    // Id to data_map and then skips it. Without the skip we would iterate
    // over all packages in the advisory and added the same adivisory Id
    // multiple times.
    dataiterator_prepend_keyname(&di, UPDATE_COLLECTION);
    while (dataiterator_step(&di)) {
        data_map.add(libdnf::advisory::AdvisoryId(di.solvid));
        dataiterator_skip_solvable(&di);
    }
    dataiterator_free(&di);

    cached_solvables_size = pool->nsolvables;
}

}  // namespace libdnf::advisory