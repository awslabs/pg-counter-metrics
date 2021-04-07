from collections import defaultdict

from pg8000.converters import (
    BIGINTEGER, BINARY, BOOLEAN, BOOLEAN_ARRAY, BYTES, CHAR, CHAR_ARRAY, DATE,
    DATETIME, DECIMAL, DECIMAL_ARRAY, FLOAT, FLOAT_ARRAY, INET, INT2VECTOR,
    INTEGER, INTEGER_ARRAY, INTERVAL, JSON, JSONB, MACADDR, NAME, NAME_ARRAY,
    NULLTYPE, NUMBER, OID, PGInterval, STRING, TEXT, TEXT_ARRAY, TIME,
    TIMEDELTA, TIMESTAMP, TIMESTAMPTZ, UNKNOWN, UUID_TYPE, VARCHAR,
    VARCHAR_ARRAY, XID)
from pg8000.core import CoreConnection
from pg8000.exceptions import DatabaseError, Error, InterfaceError


# Copyright (c) 2007-2009, Mathieu Fenniak
# Copyright (c) The Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


def to_statement(query):
    OUTSIDE = 0    # outside quoted string
    INSIDE_SQ = 1  # inside single-quote string '...'
    INSIDE_QI = 2  # inside quoted identifier   "..."
    INSIDE_ES = 3  # inside escaped single-quote string, E'...'
    INSIDE_PN = 4  # inside parameter name eg. :name
    INSIDE_CO = 5  # inside inline comment eg. --

    in_quote_escape = False
    placeholders = []
    output_query = []
    state = OUTSIDE
    prev_c = None
    for i, c in enumerate(query):
        if i + 1 < len(query):
            next_c = query[i + 1]
        else:
            next_c = None

        if state == OUTSIDE:
            if c == "'":
                output_query.append(c)
                if prev_c == 'E':
                    state = INSIDE_ES
                else:
                    state = INSIDE_SQ
            elif c == '"':
                output_query.append(c)
                state = INSIDE_QI
            elif c == '-':
                output_query.append(c)
                if prev_c == '-':
                    state = INSIDE_CO
            elif c == ":" and next_c not in ':=' and prev_c != ':':
                state = INSIDE_PN
                placeholders.append('')
            else:
                output_query.append(c)

        elif state == INSIDE_SQ:
            if c == "'":
                if in_quote_escape:
                    in_quote_escape = False
                else:
                    if next_c == "'":
                        in_quote_escape = True
                    else:
                        state = OUTSIDE
            output_query.append(c)

        elif state == INSIDE_QI:
            if c == '"':
                state = OUTSIDE
            output_query.append(c)

        elif state == INSIDE_ES:
            if c == "'" and prev_c != "\\":
                # check for escaped single-quote
                state = OUTSIDE
            output_query.append(c)

        elif state == INSIDE_PN:
            placeholders[-1] += c
            if next_c is None or (not next_c.isalnum() and next_c != '_'):
                state = OUTSIDE
                try:
                    pidx = placeholders.index(placeholders[-1], 0, -1)
                    output_query.append("$" + str(pidx + 1))
                    del placeholders[-1]
                except ValueError:
                    output_query.append("$" + str(len(placeholders)))

        elif state == INSIDE_CO:
            output_query.append(c)
            if c == '\n':
                state = OUTSIDE

        prev_c = c

    for reserved in ('types', 'stream'):
        if reserved in placeholders:
            raise InterfaceError(
                "The name '" + reserved + "' can't be used as a placeholder "
                "because it's used for another purpose.")

    def make_vals(args):
        vals = []
        for p in placeholders:
            try:
                vals.append(args[p])
            except KeyError:
                raise InterfaceError(
                    "There's a placeholder '" + p + "' in the query, but "
                    "no matching keyword argument.")
        return tuple(vals)

    return ''.join(output_query), make_vals


class Connection(CoreConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._context = None

    @property
    def columns(self):
        context = self._context
        if context is None:
            return None
        return context.columns

    @property
    def row_count(self):
        context = self._context
        if context is None:
            return None
        return context.row_count

    def run(self, sql, stream=None, types=None, **params):
        statement, make_vals = to_statement(sql)
        if types is None:
            oids = None
        else:
            oids = make_vals(defaultdict(lambda: None, types))

        self._context = self.execute_unnamed(
            statement, make_vals(params), input_oids=oids, stream=stream)
        return self._context.rows

    def prepare(self, sql):
        return PreparedStatement(self, sql)


class PreparedStatement():
    def __init__(self, con, sql):
        self.con = con
        self.statement, self.make_vals = to_statement(sql)
        self.name_map = {}

    @property
    def columns(self):
        return self._context.columns

    def run(self, stream=None, **params):
        oids, params = self.con.make_params(self.make_vals(params))

        try:
            name_bin, columns, input_funcs = self.name_map[oids]
        except KeyError:
            name_bin, columns, input_funcs = self.name_map[oids] = \
                self.con.prepare_statement(self.statement, oids)

        self._context = self.con.execute_named(
            name_bin, params, columns, input_funcs)

        return self._context.rows

    def close(self):
        for statement_name_bin, _, _ in self.name_map.values():
            self.con.close_prepared_statement(statement_name_bin)

        self.name_map.clear()


__all__ = [
    BINARY, BOOLEAN, BIGINTEGER, BOOLEAN_ARRAY, BYTES, CHAR, CHAR_ARRAY, DATE,
    DATETIME, DatabaseError, DECIMAL, DECIMAL_ARRAY, Error, FLOAT, FLOAT_ARRAY,
    INET, INT2VECTOR, INTEGER, INTEGER_ARRAY, INTERVAL, InterfaceError, JSON,
    JSONB, MACADDR, NAME, NAME_ARRAY, NULLTYPE, NUMBER, OID, PGInterval,
    STRING, TEXT, TEXT_ARRAY, TIME, TIMEDELTA, TIMESTAMP, TIMESTAMPTZ, UNKNOWN,
    UUID_TYPE, VARCHAR, VARCHAR_ARRAY, XID
]
