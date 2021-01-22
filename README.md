# yaml-adapter

![Crates.io](https://img.shields.io/crates/v/yaml-adapter)
![ci](https://github.com/casbin-rs/yaml-adapter/workflows/ci/badge.svg)

Yaml Adapter is a [yaml](https://github.com/dtolnay/serde-yaml) adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from yaml fromat file or save policy into it with fully asynchronous support.

## Dependency

Add following to `Cargo.toml`

```
yaml-adapter = { version = "0.1.0", features = "runtime-async-std" }
async-std = "1.5.0"
```

for using `tokio`

```
yaml-adapter = { version = "0.1.0", features = "runtime-tokio" }
tokio = "0.3.1"
```

## Examples

```
let adapter = YamlAdapter::new("examples/rbac_policy.yaml");
let e = Enforcer::new(m, adapter).await.unwrap();
```

for policy file configuration, please refer to [example](../examples)
