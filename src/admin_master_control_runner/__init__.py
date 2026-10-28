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

"""The provisioning runner: the half of §5.3 that executes.

The console REQUESTS (it writes a job and holds no credential); this runs on the
host that holds the deploy secrets, claims each job, and pilots the Ansible play
that builds the tenant — locally, on the server, against that server.

It is a separate package on purpose. The console's own test greps
`admin_master_control` for anything that could run a process, so the web-facing
application can never grow the ability to execute; this package is where that
ability lives, in a process with no HTTP surface at all.
"""
