use casbin::{prelude::*, DefaultModel, Enforcer, Model};
use yaml_adapter::YamlAdapter;

#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(
    all(feature = "runtime-async-std", not(target_arch = "wasm32")),
    async_std::test
)]
#[cfg_attr(
    all(feature = "runtime-tokio", not(target_arch = "wasm32")),
    tokio::test
)]
async fn test_key_match_model_in_memory() {
    let mut m = DefaultModel::default();
    m.add_def("r", "r", "sub, obj, act");
    m.add_def("p", "p", "sub, obj, act");
    m.add_def("e", "e", "some(where (p.eft == allow))");
    m.add_def(
        "m",
        "m",
        "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
    );

    let adapter = YamlAdapter::new("examples/keymatch_policy.yaml");
    let e = Enforcer::new(m, adapter).await.unwrap();
    assert_eq!(
        true,
        e.enforce(("alice", "/alice_data/resource1", "GET"))
            .unwrap()
    );
    assert_eq!(
        true,
        e.enforce(("alice", "/alice_data/resource1", "POST"))
            .unwrap()
    );
    assert_eq!(
        true,
        e.enforce(("alice", "/alice_data/resource2", "GET"))
            .unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("alice", "/alice_data/resource2", "POST"))
            .unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("alice", "/bob_data/resource1", "GET")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("alice", "/bob_data/resource1", "POST")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("alice", "/bob_data/resource2", "GET")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("alice", "/bob_data/resource2", "POST")).unwrap()
    );

    assert_eq!(
        false,
        e.enforce(("bob", "/alice_data/resource1", "GET")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("bob", "/alice_data/resource1", "POST")).unwrap()
    );
    assert_eq!(
        true,
        e.enforce(("bob", "/alice_data/resource2", "GET")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("bob", "/alice_data/resource2", "POST")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("bob", "/bob_data/resource1", "GET")).unwrap()
    );
    assert_eq!(
        true,
        e.enforce(("bob", "/bob_data/resource1", "POST")).unwrap()
    );
    assert_eq!(
        false,
        e.enforce(("bob", "/bob_data/resource2", "GET")).unwrap()
    );
    assert_eq!(
        true,
        e.enforce(("bob", "/bob_data/resource2", "POST")).unwrap()
    );

    assert_eq!(true, e.enforce(("cathy", "/cathy_data", "GET")).unwrap());
    assert_eq!(true, e.enforce(("cathy", "/cathy_data", "POST")).unwrap());
    assert_eq!(
        false,
        e.enforce(("cathy", "/cathy_data", "DELETE")).unwrap()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(
    all(feature = "runtime-async-std", not(target_arch = "wasm32")),
    async_std::test
)]
#[cfg_attr(
    all(feature = "runtime-tokio", not(target_arch = "wasm32")),
    tokio::test
)]
async fn test_implicit_permission_api_with_domain() {
    let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
        .await
        .unwrap();

    let adapter = FileAdapter::new("examples/rbac_with_hierarchy_with_domains_policy.csv");
    let mut e = Enforcer::new(m, adapter).await.unwrap();

    assert_eq!(
        vec![
            vec!["alice", "domain1", "data2", "read"],
            vec!["role:reader", "domain1", "data1", "read"],
            vec!["role:writer", "domain1", "data1", "write"],
        ],
        sort_unstable(e.get_implicit_permissions_for_user("alice", Some("domain1")))
    );
}

fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort_unstable();
    v
}
