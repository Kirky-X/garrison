#!/usr/bin/env python3
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0

"""Garrison E2E Keycloak realm 幂等供给脚本。

为 tests/acceptance 的 OAuth2/OIDC 协议验收提供真实授权服务器（Keycloak 26）：

    realm    garrison
    client   garrison-cli（confidential，四种 grant + 内省/吊销 + PKCE + scope=read）
    user     alice（密码登录 / realm 角色 admin+user / account 客户端角色
             manage-account / 自定义 claim tenant_id=42）

# 为什么走 Admin API 分步供给而非 --import-realm

Keycloak 26 的 realm 全量导入（--import-realm 与 POST /admin/realms 携带完整
representation 均同）**不会创建内置 client scopes**（basic/profile/email/roles/
web-origins），客户端引用它们只得到 "Referenced client scope ... Ignoring" 警告，
导致 id_token 缺失 sub/preferred_username/email/realm_access。而「裸 realm 创建」
（representation 仅含 realm 名）会自动建出全套内置 scopes。因此本脚本先裸建
realm 再分步注入客户端/用户/角色，全部步骤幂等（重复执行收敛到同一状态）。

# 用法

    # 依赖：docker compose 已拉起 garrison-e2e-keycloak（docker-compose.e2e.yml）
    python3 scripts/keycloak_provision.py [--base-url http://127.0.0.1:18090]

# 退出码

    0 = 供给成功且末尾自检（password grant + claims 解码）通过
    1 = 任一步骤失败（打印响应状态与内容）
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

REALM = "garrison"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"
CLIENT_ID = "garrison-cli"
CLIENT_SECRET = "garrison-cli-secret"
USER_NAME = "alice"
USER_PASSWORD = "alice-password-2026"
# 与 tests/acceptance/keycloak_fixture.rs / protocol_oauth2.rs 的 redirect_uri 一致
REDIRECT_URIS = ["https://app.example.com/callback", "http://127.0.0.1:18081/callback"]


def request(method: str, url: str, token: str | None = None, body: dict | None = None,
            form: dict | None = None, ok: tuple = (200,)):
    data = None
    headers = {}
    if form is not None:
        data = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in form.items()).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    if status not in ok:
        print(f"FATAL: {method} {url} -> {status}（期望 {ok}）: {raw[:400].decode(errors='replace')}",
              file=sys.stderr)
        sys.exit(1)
    return status, (json.loads(raw) if raw and raw.strip().startswith((b"{", b"[")) else None)


def wait_keycloak(base: str) -> None:
    """启动探测：master realm discovery 可达即就绪（最多 120s）。"""
    url = f"{base}/realms/master/.well-known/openid-configuration"
    for _ in range(60):
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(2)
    print(f"FATAL: Keycloak {base} 120s 内未就绪", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18090")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    realm_url = f"{base}/realms/{REALM}"
    admin_api = f"{base}/admin/realms"

    wait_keycloak(base)

    # 1. admin token（master realm，admin-cli password grant）
    _, tok = request("POST", f"{base}/realms/master/protocol/openid-connect/token",
                     form={"grant_type": "password", "client_id": "admin-cli",
                           "username": ADMIN_USER, "password": ADMIN_PASSWORD})
    admin = tok["access_token"]

    # 2. 幂等重建：删旧 realm（404 视同已删除）→ 裸建（触发内置 client scopes 创建）
    request("DELETE", f"{admin_api}/{REALM}", admin, ok=(204, 404))
    request("POST", admin_api, admin,
            body={"realm": REALM, "enabled": True, "sslRequired": "none",
                  "bruteForceProtected": False, "accessTokenLifespan": 300,
                  "ssoSessionIdleTimeout": 3600}, ok=(201,))

    # 2b. tenant_id 注册进 realm user profile schema——KC 24+ 默认启用
    #     declarative user profile，未注册的自定义用户属性会被静默丢弃
    _, profile = request("GET", f"{admin_api}/{REALM}/users/profile", admin)
    profile["attributes"].append({
        "name": "tenant_id", "displayName": "tenant_id", "multivalued": False,
        "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]},
        "annotations": {}, "validations": {}, "required": None,
    })
    request("PUT", f"{admin_api}/{REALM}/users/profile", admin, body=profile, ok=(200,))

    # 3. 客户端 scope "read"（scope 越权场景的合法只读 scope，出 token scope）
    request("POST", f"{admin_api}/{REALM}/client-scopes", admin,
            body={"name": "read", "description": "garrison 验收：合法只读 scope",
                  "protocol": "openid-connect",
                  "attributes": {"include.in.token.scope": "true",
                                 "display.on.consent.screen": "false"}}, ok=(201,))

    # 4. 客户端 garrison-cli：标准流 + ROPC + client_credentials + PKCE，
    #    default scopes 引用裸建产出的内置 scopes（此时必然存在）。
    #    额外挂客户端级角色 mapper：KC 26 的 roles 内置 scope 只把角色写进
    #    access token（无 id.token.claim），而 garrison 的 KeycloakClaims 契约
    #    要求 id_token 含 realm_access/resource_access。
    request("POST", f"{admin_api}/{REALM}/clients", admin,
            body={"clientId": CLIENT_ID, "enabled": True, "protocol": "openid-connect",
                  "publicClient": False, "secret": CLIENT_SECRET,
                  "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
                  "serviceAccountsEnabled": True, "redirectUris": REDIRECT_URIS,
                  "webOrigins": ["+"],
                  "defaultClientScopes": ["basic", "profile", "email", "roles", "web-origins"],
                  "optionalClientScopes": ["read"],
                  "attributes": {"post.logout.redirect.uris": "+"},
                  "protocolMappers": [
                      {"name": "tenant_id", "protocol": "openid-connect",
                       "protocolMapper": "oidc-usermodel-attribute-mapper",
                       "consentRequired": False,
                       "config": {"user.attribute": "tenant_id", "claim.name": "tenant_id",
                                  "jsonType.label": "int", "id.token.claim": "true",
                                  "access.token.claim": "true", "userinfo.token.claim": "true",
                                  "introspection.token.claim": "true"}},
                      {"name": "realm roles (id token)", "protocol": "openid-connect",
                       "protocolMapper": "oidc-usermodel-realm-role-mapper",
                       "consentRequired": False,
                       "config": {"claim.name": "realm_access.roles", "jsonType.label": "String",
                                  "multivalued": "true", "id.token.claim": "true",
                                  "access.token.claim": "true",
                                  "introspection.token.claim": "true"}},
                      {"name": "client roles (id token)", "protocol": "openid-connect",
                       "protocolMapper": "oidc-usermodel-client-role-mapper",
                       "consentRequired": False,
                       "config": {"claim.name": "resource_access.${client_id}.roles",
                                  "jsonType.label": "String", "multivalued": "true",
                                  "id.token.claim": "true", "access.token.claim": "true",
                                  "introspection.token.claim": "true"}},
                  ]}, ok=(201,))

    # 5. realm 角色 admin / user
    for role in ("admin", "user"):
        request("POST", f"{admin_api}/{REALM}/roles", admin,
                body={"name": role}, ok=(201,))

    # 6. 用户 alice：创建体只保证 username 存在，随后以全字段 PUT 落
    #    email/姓名/attributes（KC 的用户 PUT 是整字段覆盖语义，必须带全），
    #    再经 reset-password 落密码（与 PUT 凭据字段不可靠的行为解耦）。
    request("POST", f"{admin_api}/{REALM}/users", admin,
            body={"username": USER_NAME, "enabled": True}, ok=(201,))
    _, users = request("GET", f"{admin_api}/{REALM}/users?username={USER_NAME}&exact=true", admin)
    user_id = users[0]["id"]
    request("PUT", f"{admin_api}/{REALM}/users/{user_id}", admin,
            body={"username": USER_NAME, "enabled": True, "email": "alice@garrison.test",
                  "emailVerified": True, "firstName": "Alice", "lastName": "Garrison",
                  "attributes": {"tenant_id": ["42"]}}, ok=(204,))
    request("PUT", f"{admin_api}/{REALM}/users/{user_id}/reset-password", admin,
            body={"type": "password", "value": USER_PASSWORD, "temporary": False}, ok=(204,))
    _, realm_roles = request("GET", f"{admin_api}/{REALM}/roles", admin)
    by_name = {r["name"]: r for r in realm_roles}
    request("POST", f"{admin_api}/{REALM}/users/{user_id}/role-mappings/realm", admin,
            body=[{"id": by_name[r]["id"], "name": r} for r in ("admin", "user")], ok=(204,))
    # account 内置客户端的 manage-account 角色 → resource_access.account
    _, clients = request("GET", f"{admin_api}/{REALM}/clients?clientId=account", admin)
    account_id = clients[0]["id"]
    _, account_roles = request("GET", f"{admin_api}/{REALM}/clients/{account_id}/roles", admin)
    manage = next(r for r in account_roles if r["name"] == "manage-account")
    request("POST", f"{admin_api}/{REALM}/users/{user_id}/role-mappings/clients/{account_id}",
            admin, body=[{"id": manage["id"], "name": "manage-account"}], ok=(204,))

    # 7. 自检：password grant → id_token claims 齐全（sub/profile/email/roles/tenant_id）
    for attempt in range(10):
        status, token = request(
            "POST", f"{realm_url}/protocol/openid-connect/token",
            form={"grant_type": "password", "username": USER_NAME, "password": USER_PASSWORD,
                  "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                  "scope": "openid"}, ok=(200, 400, 401))
        if status == 200:
            break
        time.sleep(1)
    else:
        print("FATAL: password grant 自检失败", file=sys.stderr)
        sys.exit(1)
    payload = token["id_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    missing = [k for k in ("sub", "preferred_username", "email", "realm_access", "tenant_id")
               if not claims.get(k)]
    if missing:
        print(f"FATAL: id_token 缺失 claims: {missing}（内置 client scopes 未生效）",
              file=sys.stderr)
        sys.exit(1)
    if "account" not in claims.get("resource_access", {}):
        print("FATAL: id_token.resource_access 缺 account（客户端级角色 mapper 未生效）",
              file=sys.stderr)
        sys.exit(1)

    print(f"Keycloak realm '{REALM}' 供给完成：client={CLIENT_ID} user={USER_NAME} "
          f"claims=sub/preferred_username/email/realm_access/resource_access/tenant_id 齐全")


if __name__ == "__main__":
    main()
