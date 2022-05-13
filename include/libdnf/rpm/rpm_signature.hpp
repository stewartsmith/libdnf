/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 2.1 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIBDNF_RPM_RPM_SIGNATURE_HPP
#define LIBDNF_RPM_RPM_SIGNATURE_HPP

#include "libdnf/base/base.hpp"
#include "libdnf/common/exception.hpp"
#include "libdnf/rpm/package.hpp"

#include <rpm/rpmts.h>

namespace libdnf::rpm {

class SignatureCheckError : public Error {
public:
    using Error::Error;
    const char * get_domain_name() const noexcept override { return "libdnf::rpm"; }
    const char * get_name() const noexcept override { return "SignatureCheckError"; }
};

class RpmSignature {
public:
    enum class CheckResult { OK, FAILED_KEY_MISSING, FAILED_NOT_TRUSTED, FAILED_NOT_SIGNED, FAILED };

    explicit RpmSignature(const BaseWeakPtr & base) : base(base) {}
    explicit RpmSignature(Base & base) : RpmSignature(base.get_weak_ptr()) {}
    ~RpmSignature(){};

    CheckResult check_package_signature(Package package) const;

    //TODO(mblaha): methods for parse key and import key

private:
    BaseWeakPtr base;

    rpmts_s * create_transaction() const;
};

}  // namespace libdnf::rpm

#endif  // LIBDNF_RPM_RPM_SIGNATURE_HPP
