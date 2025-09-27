-- /etc/nginx/lua/jwt_verify.lua
-- luarocks install lua-resty-jwt
-- luarocks install lua-resty-http

local jwt = require "resty.jwt"
local cjson = require "cjson"
local http = require "resty.http"
local jwks_cache = ngx.shared.jwks_cache

-- Keycloak settings https://sohoahoso.hanas.io/realms/master/protocol/openid-connect/certs
local keycloak_host   = scheme .. "://" .. server_name --"https://sohoahoso.toaan.gov.vn"
local keycloak_realm  = "master"
local jwks_uri = keycloak_host .. "/realms/" .. keycloak_realm .. "/protocol/openid-connect/certs"

-- Extract token from Authorization header
local auth_header = ngx.var.http_Authorization
if not auth_header or auth_header:find("Bearer ") ~= 1 then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Missing or invalid Authorization header")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
local token = auth_header:sub(8)

-- Decode header to get 'kid'
local jwt_obj = jwt:load_jwt(token)
if not jwt_obj.valid then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid JWT format")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
local kid = jwt_obj.header.kid
if not kid then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Missing kid")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Get JWKS (cached)
local jwks = jwks_cache:get("jwks")
if not jwks then
    local httpc = http.new()
    local res, err = httpc:request_uri(jwks_uri, { method = "GET", ssl_verify = false })
    if not res or res.status ~= 200 then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("Failed to fetch JWKS: ", err or res.status)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    jwks = res.body
    jwks_cache:set("jwks", jwks, 3600) -- cache 1 hour
end
local jwks_json = cjson.decode(jwks)

-- Find matching key
local public_key
for _, k in ipairs(jwks_json.keys) do
    if k.kid == kid then
        local rsa = require "resty.jwt-validators.rsa"
        public_key = rsa.jwk_to_pem(k) -- convert JWK to PEM
        break
    end
end

if not public_key then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("No matching key")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Verify token
local verified = jwt:verify(public_key, token)
if not verified.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid signature: ", verified.reason)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Optional claims check "iss":"https://sohoahoso.hanas.io/realms/master"
if verified.payload.iss ~= keycloak_host .. "/realms/" .. keycloak_realm then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid issuer")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Set user info header (optional)
ngx.req.set_header("X-User", verified.payload.preferred_username)
