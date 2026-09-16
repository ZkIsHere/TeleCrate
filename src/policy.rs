//! Bucket Policy & Block Public Access (BPA) Engine M4.3.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Robust wildcard matcher supporting `*` in patterns (e.g. `arn:aws:s3:::bucket/*`, `s3:*`).
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern.eq_ignore_ascii_case(text);
    }
    let mut text_rem = text;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if text_rem.len() < part.len() || !text_rem[..part.len()].eq_ignore_ascii_case(part) {
                return false;
            }
            text_rem = &text_rem[part.len()..];
        } else if i == parts.len() - 1 {
            if text_rem.len() < part.len()
                || !text_rem[text_rem.len() - part.len()..].eq_ignore_ascii_case(part)
            {
                return false;
            }
        } else {
            let lower_rem = text_rem.to_lowercase();
            let lower_part = part.to_lowercase();
            if let Some(pos) = lower_rem.find(&lower_part) {
                text_rem = &text_rem[pos + part.len()..];
            } else {
                return false;
            }
        }
    }
    true
}

pub use crate::db::BucketBpa;

pub fn parse_bpa_xml(xml: &str) -> Result<BucketBpa, String> {
    quick_xml::de::from_str(xml)
        .map_err(|e| format!("Invalid XML PublicAccessBlockConfiguration: {e}"))
}

pub fn serialize_bpa_xml(bpa: &BucketBpa) -> Result<String, String> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let xml_str = quick_xml::se::to_string(bpa).map_err(|e| format!("Serialize BPA XML: {e}"))?;
    out.push_str(&xml_str);
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    Single(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    pub fn matches(&self, target: &str) -> bool {
        match self {
            StringOrVec::Single(s) => wildcard_match(s, target),
            StringOrVec::Vec(v) => v.iter().any(|s| wildcard_match(s, target)),
        }
    }

    pub fn is_wildcard(&self) -> bool {
        match self {
            StringOrVec::Single(s) => s == "*",
            StringOrVec::Vec(v) => v.iter().any(|s| s == "*"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalValue {
    Wildcard(String),
    Map(HashMap<String, StringOrVec>),
}

impl PrincipalValue {
    pub fn is_public(&self) -> bool {
        match self {
            PrincipalValue::Wildcard(s) => s == "*",
            PrincipalValue::Map(m) => {
                if let Some(aws) = m.get("AWS") {
                    aws.is_wildcard()
                } else {
                    false
                }
            }
        }
    }

    pub fn matches_user(&self, user_id: &str) -> bool {
        if self.is_public() {
            return true;
        }
        match self {
            PrincipalValue::Wildcard(_) => true,
            PrincipalValue::Map(m) => {
                if let Some(aws) = m.get("AWS") {
                    aws.matches(user_id)
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    pub sid: Option<String>,
    pub effect: String, // "Allow" or "Deny"
    pub principal: PrincipalValue,
    pub action: StringOrVec,
    pub resource: StringOrVec,
    pub condition: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    pub version: Option<String>,
    #[serde(default)]
    pub statement: Vec<PolicyStatement>,
}

impl PolicyDocument {
    pub fn is_public(&self) -> bool {
        self.statement
            .iter()
            .any(|stmt| stmt.effect.eq_ignore_ascii_case("Allow") && stmt.principal.is_public())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvalResult {
    Allow,
    Deny,
    NoMatch,
}

pub fn eval_policy(
    policy_json: &str,
    bucket: &str,
    key: Option<&str>,
    action: &str,
    user_id: &str, // e.g. "root", "TESTKEY123", or "anonymous"
    bpa: Option<&BucketBpa>,
) -> PolicyEvalResult {
    let doc: PolicyDocument = match serde_json::from_str(policy_json) {
        Ok(d) => d,
        Err(_) => return PolicyEvalResult::NoMatch,
    };

    let target_resource = match key {
        Some(k) => format!("arn:aws:s3:::{bucket}/{k}"),
        None => format!("arn:aws:s3:::{bucket}"),
    };

    let is_anonymous = user_id.eq_ignore_ascii_case("anonymous");

    // Check BPA restricting public buckets
    let block_public = bpa.is_some_and(|b| b.block_public_policy || b.restrict_public_buckets);

    let mut has_allow = false;

    for stmt in &doc.statement {
        let is_deny = stmt.effect.eq_ignore_ascii_case("Deny");
        let is_allow = stmt.effect.eq_ignore_ascii_case("Allow");

        if !is_deny && !is_allow {
            continue;
        }

        // If user is anonymous and BPA blocks public access, skip public allow statements!
        if is_anonymous && is_allow && stmt.principal.is_public() && block_public {
            continue;
        }

        if !stmt.principal.matches_user(user_id) {
            continue;
        }

        if !stmt.action.matches(action) {
            continue;
        }

        if !stmt.resource.matches(&target_resource) {
            continue;
        }

        if is_deny {
            return PolicyEvalResult::Deny;
        }
        if is_allow {
            has_allow = true;
        }
    }

    if has_allow {
        PolicyEvalResult::Allow
    } else {
        PolicyEvalResult::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match(
            "arn:aws:s3:::bkt/*",
            "arn:aws:s3:::bkt/file.txt"
        ));
        assert!(!wildcard_match(
            "arn:aws:s3:::bkt/*",
            "arn:aws:s3:::other/file.txt"
        ));
        assert!(wildcard_match("s3:*", "s3:GetObject"));
    }

    #[test]
    fn test_policy_eval_allow_and_deny() {
        let json = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/*"
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/secret.txt"
                }
            ]
        }"#;

        assert_eq!(
            eval_policy(
                json,
                "mybucket",
                Some("file.txt"),
                "s3:GetObject",
                "anonymous",
                None
            ),
            PolicyEvalResult::Allow
        );
        assert_eq!(
            eval_policy(
                json,
                "mybucket",
                Some("secret.txt"),
                "s3:GetObject",
                "anonymous",
                None
            ),
            PolicyEvalResult::Deny
        );
    }
}
