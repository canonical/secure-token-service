# Changelog

## [0.7.0](https://github.com/canonical/secure-token-service/compare/v0.6.0...v0.7.0) (2026-10-16)


### Features

* **auth:** add Hydra token verifier with preemptive JWKS caching ([983d3db](https://github.com/canonical/secure-token-service/commit/983d3db971515c195dfa1c64b9862ac16ba05ad7))
* **auth:** implement Ubuntu One OpenID 2.0 client and claims extraction ([80eb98f](https://github.com/canonical/secure-token-service/commit/80eb98fa3956deeec5e78ae2bdfde20af742cb75))
* **build:** support amd64, arm64, and riscv64 Go binary compilation ([9d77f23](https://github.com/canonical/secure-token-service/commit/9d77f23a67d0b257430d74d0e3dafa6cff5a7c98))
* **build:** support multi-arch binaries (amd64, arm64, riscv64) and rocks (amd64, arm64) ([#52](https://github.com/canonical/secure-token-service/issues/52)) ([3b09e93](https://github.com/canonical/secure-token-service/commit/3b09e93ef4fc6f793a8a81edecb6754b1cd4fbbd))
* **ci:** shift-left vulnerability check & release quarantine gate ([e55ad87](https://github.com/canonical/secure-token-service/commit/e55ad8714496695a102a9860642561a2a2024bbf))
* **ci:** shift-left vulnerability check & release quarantine gate ([#34](https://github.com/canonical/secure-token-service/issues/34)) ([c90af84](https://github.com/canonical/secure-token-service/commit/c90af8495fcfb87c5205f9128e8c092a7e028ec0))
* **config,session:** add Ubuntu One config and extend Session with Provider and Claims ([68b7564](https://github.com/canonical/secure-token-service/commit/68b756459769c42802856a14e7d1e95727dfd751))
* **cookie:** standardize session and auth state cookies with dynamic TLS security ([fa476f5](https://github.com/canonical/secure-token-service/commit/fa476f5889f7e8c3267d07f431f44e1ffccddc40))
* **grpc:** implement ExchangeToken RPC for IdP client credentials token exchange ([#47](https://github.com/canonical/secure-token-service/issues/47)) ([cfb972a](https://github.com/canonical/secure-token-service/commit/cfb972a3a2b818518c2eda8cb43f175e0f3b83dc)), closes [#44](https://github.com/canonical/secure-token-service/issues/44)
* **grpc:** implement ExchangeToken RPC with expiration clamping and synthetic email ([4ee3f3c](https://github.com/canonical/secure-token-service/commit/4ee3f3c762ff302a7e85cf49de419fe7a101afe1))
* **grpc:** propagate normalized session claims into internal JWT ([1f4056e](https://github.com/canonical/secure-token-service/commit/1f4056ea823c43c5d3e0f38085631693b04952fb))
* **http:** add /auth/openid/callback and support provider switching in /auth/login ([723d476](https://github.com/canonical/secure-token-service/commit/723d47612f4794281d68be0ad79c988ff907044b))
* **http:** enable multi-provider selection in dummy frontend for local testing ([6199fc9](https://github.com/canonical/secure-token-service/commit/6199fc9b3e6ce8f865bcdc950a59402d4f0fb07d))
* **observability:** add M2M token exchange metrics and update gRPC documentation ([5f4b1bd](https://github.com/canonical/secure-token-service/commit/5f4b1bd91fcef8946d461be3228cfb7aa84b11ca))
* **proto:** define ExchangeToken RPC and ExchangeTokenRequest message ([9e54cb5](https://github.com/canonical/secure-token-service/commit/9e54cb5c1dddacfe43b51f8ba12fffdba3b107cc))
* **rock:** support amd64 and arm64 in rockcraft and container build configs ([dc04dd8](https://github.com/canonical/secure-token-service/commit/dc04dd85c277ea1b45ec445ebae19f0462a18481))
* **spec:** add specification for m2m client credentials token exchange ([#44](https://github.com/canonical/secure-token-service/issues/44)) ([171fb55](https://github.com/canonical/secure-token-service/commit/171fb5584783716295a04669f3eedeb75b80f5d4))
* **spec:** add specification for ubuntu one openid support and standardized cookies ([3ba2728](https://github.com/canonical/secure-token-service/commit/3ba2728aed477feeab4038edcda12ec5a6f57f5b))


### Bug Fixes

* **build:** address review feedback on multi-arch builds and specs ([2019588](https://github.com/canonical/secure-token-service/commit/2019588d702b689fde15c9ae1d824272cd937189))
* **ci:** address PR review comments and bump identity-team workflows to v1.17.1 ([95af510](https://github.com/canonical/secure-token-service/commit/95af5107d99890ec4df35e1a10ffbbab25095ddf))
* **deploy:** configure skaffold with podman and rockcraft skopeo, align otel semconv ([b4426b8](https://github.com/canonical/secure-token-service/commit/b4426b8950f5d892bdf1631cc086c769608ad218))
* **grpc:** enforce max token size, validate machine claims, add audit logging, and manage verifier lifecycle ([2b13e6c](https://github.com/canonical/secure-token-service/commit/2b13e6cebd1e5f8b8393442c1988b5165d49de9d))
* resolve CodeQL cookie alerts and OpenCode review issues for Ubuntu One OpenID ([30c7d19](https://github.com/canonical/secure-token-service/commit/30c7d1955e81d1e62c91aca04fbed9f1d0f3e215))

## [0.6.0](https://github.com/canonical/secure-token-service/compare/v0.5.0...v0.6.0) (2026-09-10)


### Features

* **openspec:** add openspec-detect-drift agent skill ([0ff8c46](https://github.com/canonical/secure-token-service/commit/0ff8c462eb005379dddfe44565f99b9d62993844))

## [0.5.0](https://github.com/canonical/secure-token-service/compare/v0.4.0...v0.5.0) (2026-09-09)


### Features

* **openspec:** configure openspec and add opencode/openspec workflows ([a0c1fdc](https://github.com/canonical/secure-token-service/commit/a0c1fdc2806c4d289d47f7345b11d64a8d93759a))
* **openspec:** configure openspec and add opencode/openspec workflows ([#28](https://github.com/canonical/secure-token-service/issues/28)) ([bd6d8ea](https://github.com/canonical/secure-token-service/commit/bd6d8ea4f7a9ea2af79a237cec39d5283ec761d4))


### Bug Fixes

* **cookie:** error out if cookie key is too short ([#7](https://github.com/canonical/secure-token-service/issues/7)) ([6ff719c](https://github.com/canonical/secure-token-service/commit/6ff719ccf09c4870e09d246dbb9810f64034feec))
* **http:** verify return_to parameter to prevent open redirect ([#6](https://github.com/canonical/secure-token-service/issues/6)) ([4c1dc86](https://github.com/canonical/secure-token-service/commit/4c1dc86f61481407372c7ca729d2e280940ff7c7))

## [0.4.0](https://github.com/canonical/secure-token-service/compare/v0.3.0...v0.4.0) (2026-04-01)


### Features

* add CACHE_USERNAME config option for Valkey/Redis ([0c6b30e](https://github.com/canonical/secure-token-service/commit/0c6b30e664b985f182a6c3d6d933f9ed31f83b65))

## [0.3.0](https://github.com/canonical/secure-token-service/compare/v0.2.1...v0.3.0) (2026-03-30)


### Features

* switch JWT signing from RSA (RS256) to ECDSA (ES256) ([241dcaf](https://github.com/canonical/secure-token-service/commit/241dcafa8eeefc5babec8a9013d141d5119b6886))


### Bug Fixes

* initialize metrics instruments when metrics provider is disabled ([4a9c2cb](https://github.com/canonical/secure-token-service/commit/4a9c2cb6e6ff08f8920d65c09b5879adc641e879))
* initialize metrics instruments when metrics provider is disabled ([#20](https://github.com/canonical/secure-token-service/issues/20)) ([975012d](https://github.com/canonical/secure-token-service/commit/975012dd79aaa81fb775ea529acd59c126794638))

## [0.2.1](https://github.com/canonical/secure-token-service/compare/v0.2.0...v0.2.1) (2026-03-20)


### Bug Fixes

* ci artifact name ([f2380a7](https://github.com/canonical/secure-token-service/commit/f2380a73ac775398e5dc6f3e9d59999b6c1c70e1))
* ci artifact name ([#15](https://github.com/canonical/secure-token-service/issues/15)) ([6bccf2c](https://github.com/canonical/secure-token-service/commit/6bccf2cd7d9a39280c17dead649d106b978d6a88))

## [0.2.0](https://github.com/canonical/secure-token-service/compare/v0.1.0...v0.2.0) (2026-03-20)


### Features

* add gRPC reflection ([a8fdd48](https://github.com/canonical/secure-token-service/commit/a8fdd4874f2d3b57f4a89eca79a7d20a4f5cc655))
* add key rotation setup ([85cc9c6](https://github.com/canonical/secure-token-service/commit/85cc9c6f49f7e37a346adc2a5a78c793ed7d6fbf))
* add observability ([a400825](https://github.com/canonical/secure-token-service/commit/a4008256fbc472db1b67b1bf306034c1f240b5b5))
* add protobuf definition for grpc methods ([6678049](https://github.com/canonical/secure-token-service/commit/66780491bd3a81fb232359622bb444352e9499ed))
* add session extender commands ([6e97b3b](https://github.com/canonical/secure-token-service/commit/6e97b3bd71f9e1feba901e825363bbc9a3c6a632))
* add version command ([375c5fa](https://github.com/canonical/secure-token-service/commit/375c5fa94d803932afbd9af7acb62b6fa58b6c25))
* **cmd:** add goose for migrations ([802796b](https://github.com/canonical/secure-token-service/commit/802796bea737c8b5228d67c5076aff52fd8304e1))
* core application bootstrap ([1d2e7b9](https://github.com/canonical/secure-token-service/commit/1d2e7b947e15b5a6360e1e4dfb91c925fa4f2ed0))
* implement oidc dance with http endpoints ([8204a9a](https://github.com/canonical/secure-token-service/commit/8204a9a186880951b5e33a365a48ecef963ddaf0))


### Bug Fixes

* add release-please manifest ([5a08cec](https://github.com/canonical/secure-token-service/commit/5a08cecce947cddba6b94631913cb3596330f2d8))
* add release-please manifest ([#11](https://github.com/canonical/secure-token-service/issues/11)) ([c58dfd3](https://github.com/canonical/secure-token-service/commit/c58dfd33ea76882eedc818aedb38b926b99d3084))
* use chmike/securecookie library ([bf2f093](https://github.com/canonical/secure-token-service/commit/bf2f093d48f3a8adbe6aaeabff371a43b1ca606b))
