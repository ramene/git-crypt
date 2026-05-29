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

#ifndef GIT_CRYPT_LICENSE_COMMANDS_HPP
#define GIT_CRYPT_LICENSE_COMMANDS_HPP

#include <iosfwd>

// License subcommands (return 0=ok, 1=error, 2=usage)
int	license_cmd_init (int argc, const char** argv);
int	license_cmd_issue (int argc, const char** argv);
int	license_cmd_verify (int argc, const char** argv);
int	license_cmd_revoke (int argc, const char** argv);
int	license_cmd_list (int argc, const char** argv);
int	license_cmd_show (int argc, const char** argv);
int	license_cmd_anchor (int argc, const char** argv);
int	license_cmd_import (int argc, const char** argv);
int	license_cmd_export (int argc, const char** argv);
int	license_cmd_check (int argc, const char** argv);
int	license_cmd_serve (int argc, const char** argv);

// Help messages
void	help_license_init (std::ostream&);
void	help_license_issue (std::ostream&);
void	help_license_verify (std::ostream&);
void	help_license_revoke (std::ostream&);
void	help_license_list (std::ostream&);
void	help_license_show (std::ostream&);
void	help_license_anchor (std::ostream&);
void	help_license_import (std::ostream&);
void	help_license_export (std::ostream&);
void	help_license_check (std::ostream&);
void	help_license_serve (std::ostream&);

#endif
