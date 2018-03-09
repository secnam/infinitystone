# -*- coding: utf-8 -*-
# Copyright (c) 2018 Christiaan Frans Rademan.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holders nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
from luxon import GetLogger
from luxon import register_resource
from luxon import register_resources
from luxon import g
from luxon.exceptions import ValidationError
from luxon import db
from luxon.utils.timezone import now

from uuid import uuid4
import json


from infinitystone.utils.auth import user_domains

log = GetLogger(__name__)

def checkUnique(conn, id, role, domain, tenant_id):
    """Function to check if use role is Unique.

    Args:
        conn (obj): DB connection object.
        id (str): UUID of user.
        role (str): UUID of role.
        domain (str): Name of the domain.
        tenant_id (str): UUID of the tenant.
    """
    sql = "SELECT id FROM luxon_user_role WHERE " \
          "user_id=? AND role_id=? AND domain "
    vals = [id, role]
    if domain is None:
        sql += "IS NULL"
    else:
        sql += "=?"
        vals.append(domain)
    if tenant_id is None:
        sql += " AND tenant_id IS NULL"
    else:
        sql += " AND tenant_id=?"
        vals.append(tenant_id)

    cur = conn.execute(sql, (vals))
    if cur.fetchone():
        raise ValidationError("Entry for user %s role %s " \
                              "already exists on domain %s" \
                              " and tenant %s. PUT don't POST" \
                              % (id, role, domain, tenant_id))

@register_resource('GET', '/v1/rbac/domains')
def rbac_domains(req, resp):
    search = req.query_params.get('term')
    domains_list = user_domains(req.token.user_id)
    if search is not None:
        filtered = []
        for domain in domains_list:
            if search in domain:
                filtered.append(domain)
        return filtered
    return domains_list

@register_resource('GET', '/v1/rbac/user/{id}')
def user_roles(req, resp, id):
    pass

@register_resources()
class UserRoles():
    def __init__(self):
        g.router.add('POST', '/v1/rbac/user/{id}/{role}',
                     self.add_user_role, tag="admin")
        g.router.add('POST', '/v1/rbac/user/{id}/{role}/{domain}',
                     self.add_user_role, tag="admin")
        g.router.add('POST', '/v1/rbac/user/{id}/{role}/{domain}/{tenant_id}',
                     self.add_user_role, tag="admin")

    def add_user_role(self, req, resp, id, role, domain=None, tenant_id=None):
        with db() as conn:
            # Even though we have unique constraint, sqlite
            # does not consider null as unique:
            # ref https://stackoverflow.com/questions/22699409/sqlite-null-and-unique
            # So need to manually check that
            checkUnique(conn, id, role, domain, tenant_id)

            sql = "INSERT INTO luxon_user_role "\
                  "(`id`,`role_id`,`tenant_id`,`user_id`," \
                  "`domain`,`creation_time`) "\
                  "VALUES (?,?,?,?,?,?)"
            user_role_id = str(uuid4())
            conn.execute(sql, (user_role_id, role, tenant_id,
                               id, domain, now()))
            conn.commit()
            user_role = {"id": user_role_id,
                         "user_id": id,
                         "role_id": role,
                         "domain": domain,
                         "tenant_id": tenant_id}
            return json.dumps(user_role, indent=4)

@register_resource('DELETE', '/v1/rbac/user/{id}/{role}')
@register_resource('DELETE', '/v1/rbac/user/{id}/{role}/{domain}')
@register_resource('DELETE', '/v1/rbac/user/{id}/{role}/{domain}/{tenant_id}')
def rm_user_role(req, resp, id, role, domain=None, tenant_id=None):
    pass

