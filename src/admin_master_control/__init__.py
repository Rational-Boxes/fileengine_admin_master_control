# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""FileEngine deployment-tier administration.

See design_documents/PROPOSAL_system_administration_application.md. The two
sentences worth knowing before reading any other module:

* This is the first door that reads ACROSS the tenant boundary on purpose, so
  it inherits nothing from the doors that read one tenant (§2, §4).
* It observes and records decisions. It executes nothing destructive, holds no
  cloud credential, and never reads file content (§4).
"""

__version__ = "0.1.0"
