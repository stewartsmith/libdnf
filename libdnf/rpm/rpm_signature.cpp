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

#include "libdnf/rpm/rpm_signature.hpp"

#include "rpm/rpm_log_guard.hpp"
#include "utils/bgettext/bgettext-lib.h"

#include "libdnf/repo/repo.hpp"

#include <rpm/rpmcli.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>

namespace libdnf::rpm {

rpmts_s * RpmSignature::create_transaction() const {
    auto ts = rpmtsCreate();
    auto & config = base->get_config();
    auto root_dir = config.installroot().get_value();
    if (rpmtsSetRootDir(ts, root_dir.c_str()) != 0) {
        throw SignatureCheckError(M_("Cannot set root directory \"{}\""), std::string(root_dir));
    }
    return ts;
}

RpmSignature::CheckResult RpmSignature::check_package_signature(rpm::Package pkg) const {
    // is package gpg check needed?
    auto repo = pkg.get_repo();
    if (repo->get_type() == libdnf::repo::Repo::Type::COMMANDLINE) {
        if (!base->get_config().localpkg_gpgcheck().get_value()) {
            return CheckResult::OK;
        }
    } else {
        auto & repo_config = repo->get_config();
        if (!repo_config.gpgcheck().get_value()) {
            return CheckResult::OK;
        }
    }

    // rpmcliVerifySignatures is the only API rpm provides for signature verification.
    // Unfortunatelly to distinguish key_missing/not_signed/verification_failed cases
    // we need to temporarily increase log level to RPMLOG_INFO, collect the log
    // messages and parse them.
    // This code is only slightly better than running `rpmkeys --checksig` tool
    // and parsing it's output :(

    // This guard acquires the rpm log mutex and collects all rpm log messages into
    // the vector of strings.
    libdnf::rpm::RpmLogGuardStrings rpm_log_guard;

    auto ts = create_transaction();
    auto oldmask = rpmlogSetMask(RPMLOG_UPTO(RPMLOG_PRI(RPMLOG_INFO)));

    rpmtsSetVfyLevel(ts, RPMSIG_SIGNATURE_TYPE);
    std::string path = pkg.get_package_path();
    char * const path_array[2] = {&path[0], NULL};
    auto rc = rpmcliVerifySignatures(ts, path_array);

    rpmlogSetMask(oldmask);
    rpmtsFree(ts);

    if (rc == RPMRC_OK) {
        return CheckResult::OK;
    }

    // This is brittle and heavily depends on rpm not changing log messages.
    // Here is an example of log messages after verifying a signed package
    // but without public key present in rpmdb:
    //   /path/to/rpm/dummy-signed-1.0.1-0.x86_64.rpm:
    //       Header V4 EdDSA/SHA512 Signature, key ID 773dd1ba: NOKEY
    //       Header RSA signature: NOTFOUND
    //       Header SHA256 digest: OK
    //       Header SHA1 digest: OK
    //       Payload SHA256 digest: OK
    //       RSA signature: NOTFOUND
    //       DSA signature: NOTFOUND
    //       MD5 digest: OK
    bool missing_key{false};
    bool not_trusted{false};
    bool not_signed{false};
    for (const auto & line : rpm_log_guard.get_rpm_logs()) {
        std::string_view line_v{line};
        if (line_v.starts_with(path)) {
            continue;
        }
        if (line.find(": BAD") != std::string::npos) {
            return CheckResult::FAILED;
        }
        if (line_v.ends_with(": NOKEY")) {
            missing_key = true;
        } else if (line_v.ends_with(": NOTTRUSTED")) {
            not_trusted = true;
        } else if (line_v.ends_with(": NOTFOUND")) {
            not_signed = true;
        } else if (!line_v.ends_with(": OK")) {
            return CheckResult::FAILED;
        }
    }
    if (not_trusted) {
        return CheckResult::FAILED_NOT_TRUSTED;
    } else if (missing_key) {
        return CheckResult::FAILED_KEY_MISSING;
    } else if (not_signed) {
        return CheckResult::FAILED_NOT_SIGNED;
    }
    return CheckResult::FAILED;
}


}  //  namespace libdnf::rpm
