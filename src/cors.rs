//! CORS Engine M4.3: parsing XML CORSConfiguration, matching rule, returning response headers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CorsRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "AllowedOrigin", default)]
    pub allowed_origin: Vec<String>,
    #[serde(rename = "AllowedMethod", default)]
    pub allowed_method: Vec<String>,
    #[serde(rename = "AllowedHeader", default)]
    pub allowed_header: Vec<String>,
    #[serde(
        rename = "MaxAgeSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_age_seconds: Option<u32>,
    #[serde(rename = "ExposeHeader", default)]
    pub expose_header: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "CORSConfiguration", rename_all = "PascalCase")]
pub struct CorsConfiguration {
    #[serde(rename = "CORSRule", default)]
    pub cors_rule: Vec<CorsRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsMatch {
    pub allow_origin: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub expose_headers: String,
    pub max_age_seconds: Option<u32>,
}

pub fn parse_cors_xml(xml: &str) -> Result<CorsConfiguration, String> {
    quick_xml::de::from_str(xml).map_err(|e| format!("Invalid XML CORSConfiguration: {e}"))
}

pub fn serialize_cors_xml(cors: &CorsConfiguration) -> Result<String, String> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let xml_str = quick_xml::se::to_string(cors).map_err(|e| format!("Serialize CORS XML: {e}"))?;
    out.push_str(&xml_str);
    Ok(out)
}

/// Dynamic CORS rule matcher against incoming request headers.
pub fn match_cors_rule(
    cors: &CorsConfiguration,
    origin: &str,
    method: &str,
    req_headers: Option<&str>,
) -> Option<CorsMatch> {
    for rule in &cors.cors_rule {
        // 1. Match Origin
        let origin_matched = rule.allowed_origin.iter().any(|o| {
            o == "*" || o.eq_ignore_ascii_case(origin) || crate::policy::wildcard_match(o, origin)
        });
        if !origin_matched {
            continue;
        }

        // 2. Match Method
        let method_matched = rule
            .allowed_method
            .iter()
            .any(|m| m == "*" || m.eq_ignore_ascii_case(method));
        if !method_matched {
            continue;
        }

        // 3. Match Request Headers (if requested)
        if let Some(headers_str) = req_headers {
            let req_hdrs: Vec<&str> = headers_str
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            let headers_matched = req_hdrs.iter().all(|req_h| {
                rule.allowed_header
                    .iter()
                    .any(|h| h == "*" || h.eq_ignore_ascii_case(req_h))
            });
            if !headers_matched {
                continue;
            }
        }

        // Rule matched!
        let allow_origin = if rule.allowed_origin.iter().any(|o| o == "*") {
            "*".to_string()
        } else {
            origin.to_string()
        };

        let allow_methods = rule.allowed_method.join(", ");
        let allow_headers = if let Some(h) = req_headers {
            h.to_string()
        } else {
            rule.allowed_header.join(", ")
        };
        let expose_headers = rule.expose_header.join(", ");

        return Some(CorsMatch {
            allow_origin,
            allow_methods,
            allow_headers,
            expose_headers,
            max_age_seconds: rule.max_age_seconds,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_xml_parse_and_serialize() {
        let xml = r#"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader><MaxAgeSeconds>3000</MaxAgeSeconds><ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>"#;
        let parsed = parse_cors_xml(xml).unwrap();
        assert_eq!(parsed.cors_rule.len(), 1);
        assert_eq!(parsed.cors_rule[0].allowed_method, vec!["GET", "PUT"]);

        let match_res =
            match_cors_rule(&parsed, "http://example.com", "GET", Some("content-type")).unwrap();
        assert_eq!(match_res.allow_origin, "*");
        assert_eq!(match_res.allow_methods, "GET, PUT");
    }
}
