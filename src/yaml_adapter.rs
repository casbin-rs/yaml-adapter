use crate::ParsePolicyFailed;
use async_trait::async_trait;
use casbin::{error::AdapterError, error::ModelError, Adapter, Error, Filter, Model, Result};
use linked_hash_map::LinkedHashMap;
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

#[cfg(feature = "runtime-async-std")]
use async_std::{
    fs::File,
    io::prelude::*,
    io::{Error as IoError, ErrorKind},
    path::Path,
};

#[cfg(feature = "runtime-tokio")]
use std::{
    io::{Error as IoError, ErrorKind},
    path::Path,
};
#[cfg(feature = "runtime-tokio")]
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

pub struct YamlAdapter<P> {
    file_path: P,
    is_filtered: bool,
}

#[async_trait]
impl<P> Adapter for YamlAdapter<P>
where
    P: AsRef<Path> + Send + Sync,
{
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        self.load_filtered_policy_into_model(
            m,
            Filter {
                p: Vec::new(),
                g: Vec::new(),
            },
        )
        .await?;
        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        self.is_filtered = self.load_filtered_policy_into_model(m, f).await?;
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        if self.file_path.as_ref().as_os_str().is_empty() {
            return Err(
                IoError::new(ErrorKind::Other, "save policy failed, file path is empty").into(),
            );
        }

        let mut policies = LinkedHashMap::<_, _>::new();
        let ast_map = m
            .get_model()
            .get("p")
            .ok_or_else(|| ModelError::P("Missing policy definition in conf file".to_owned()))?;

        for (ptype, ast) in ast_map {
            policies.insert(
                Yaml::from_str(ptype),
                Yaml::Array(
                    ast.get_policy()
                        .iter()
                        .map(|p| {
                            Yaml::Array(p.iter().map(|s| Yaml::from_str(s)).collect::<Vec<Yaml>>())
                        })
                        .collect::<Vec<Yaml>>(),
                ),
            );
        }

        let mut buf = String::new();
        let mut emitter = YamlEmitter::new(&mut buf);
        if let Err(err) = emitter.dump(&Yaml::Hash(policies)) {
            return Err(Error::AdapterError(AdapterError(Box::new(err))));
        }
        std::mem::drop(emitter);

        //FIXME
        //self.save_policy_file(buf).await?;
        return Ok(());
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.save_policy_file(String::new()).await?;
        Ok(())
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<String>) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convenience
        Ok(true)
    }
}

impl<P> YamlAdapter<P>
where
    P: AsRef<Path> + Send + Sync,
{
    pub fn new(p: P) -> YamlAdapter<P> {
        YamlAdapter {
            file_path: p,
            is_filtered: false,
        }
    }

    async fn save_policy_file(&self, text: String) -> Result<()> {
        let mut file = File::create(&self.file_path).await?;
        file.write_all(text.as_bytes()).await?;
        Ok(())
    }

    async fn load_yaml(&self) -> Result<Yaml> {
        let mut fd = File::open(&self.file_path).await?;
        let mut buf = String::new();
        let _ = fd.read_to_string(&mut buf).await;

        let docs = match YamlLoader::load_from_str(buf.as_ref()) {
            Ok(yaml) => yaml,
            Err(err) => return Err(Error::AdapterError(AdapterError(Box::new(err)))),
        };
        Ok(docs
            .into_iter()
            .next()
            .ok_or(ParsePolicyFailed("there should be a doc".to_string()))?)
    }

    async fn load_filtered_policy_into_model<'a>(
        &self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<bool> {
        let doc = self.load_yaml().await?;
        let mut filtered = false;
        for (ptype, polices) in doc
            .into_hash()
            .ok_or(AdapterError(Box::new(ParsePolicyFailed(
                "top level should be map".to_string(),
            ))))?
        {
            let ptype = ptype
                .into_string()
                .ok_or(AdapterError(Box::new(ParsePolicyFailed(
                    "ptype should be string".to_string(),
                ))))?;
            let polices = polices
                .into_vec()
                .ok_or(AdapterError(Box::new(ParsePolicyFailed(
                    "policy should be array".to_string(),
                ))))?;
            let sec = ptype
                .chars()
                .next()
                .map(|x| x.to_string())
                .ok_or(ParsePolicyFailed("ptype should be string".to_string()))?;
            let f = if sec.eq_ignore_ascii_case("p") {
                f.p.clone()
            } else {
                f.g.clone()
            };
            if f.contains(&ptype.as_ref()) {
                filtered = true;
                continue;
            }
            for policy in polices {
                let policy = policy
                    .into_vec()
                    .ok_or(ParsePolicyFailed("policy should be array".to_string()))?
                    .into_iter()
                    .map(|s| s.into_string().unwrap())
                    .collect();
                m.add_policy(&sec, &ptype, policy);
            }
        }
        Ok(filtered)
    }
}
