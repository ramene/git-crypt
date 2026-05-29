/*
 * Copyright 2024 git-crypt-revived contributors
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#ifndef GIT_CRYPT_TRUSTLESS_COMMANDS_HPP
#define GIT_CRYPT_TRUSTLESS_COMMANDS_HPP

#include <iosfwd>

// Trustless subcommands (return 0=ok, 1=error, 2=usage)
int	trustless_cmd_init (int argc, const char** argv);
int	trustless_cmd_deploy (int argc, const char** argv);
int	trustless_cmd_issue (int argc, const char** argv);
int	trustless_cmd_verify (int argc, const char** argv);
int	trustless_cmd_revoke (int argc, const char** argv);
int	trustless_cmd_list (int argc, const char** argv);
int	trustless_cmd_show (int argc, const char** argv);
int	trustless_cmd_check (int argc, const char** argv);
int	trustless_cmd_export (int argc, const char** argv);
int	trustless_cmd_import (int argc, const char** argv);
int	trustless_cmd_migrate (int argc, const char** argv);
int	trustless_cmd_prove (int argc, const char** argv);
int	trustless_cmd_verify_proof (int argc, const char** argv);
int	trustless_cmd_audit_root (int argc, const char** argv);
int	trustless_cmd_audit_prove (int argc, const char** argv);
int	trustless_cmd_audit_verify (int argc, const char** argv);
int	trustless_cmd_config (int argc, const char** argv);
int	trustless_cmd_serve (int argc, const char** argv);

// Help messages
void	help_trustless_init (std::ostream&);
void	help_trustless_deploy (std::ostream&);
void	help_trustless_issue (std::ostream&);
void	help_trustless_verify (std::ostream&);
void	help_trustless_revoke (std::ostream&);
void	help_trustless_list (std::ostream&);
void	help_trustless_show (std::ostream&);
void	help_trustless_check (std::ostream&);
void	help_trustless_export (std::ostream&);
void	help_trustless_import (std::ostream&);
void	help_trustless_migrate (std::ostream&);
void	help_trustless_prove (std::ostream&);
void	help_trustless_verify_proof (std::ostream&);
void	help_trustless_audit_root (std::ostream&);
void	help_trustless_audit_prove (std::ostream&);
void	help_trustless_audit_verify (std::ostream&);
void	help_trustless_config (std::ostream&);
void	help_trustless_serve (std::ostream&);

#endif
