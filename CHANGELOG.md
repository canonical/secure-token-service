# Changelog

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
