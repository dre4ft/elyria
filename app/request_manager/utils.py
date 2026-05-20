# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import uuid_utils

def _generate_request_uuid()->str:
    return str(uuid_utils.uuid4())
