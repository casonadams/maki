use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::providers::ResolvedAuth;
use crate::{ContentBlock, Message, Role};

use super::shared::SystemBlock;

const BILLING_SALT: &str = "59cf53e54c78";
const FALLBACK_CC_VERSION: &str = "2.1.224";
const CC_ENTRYPOINT: &str = "sdk-cli";
const AGENT_SDK_IDENTITY: &str = "You are a Claude agent, built on Anthropic's Claude Agent SDK.";

const CCH_SEED: u64 = 0x4d65_9218_e32a_3268;
const PRIME64_1: u64 = 0x9e37_79b1_85eb_ca87;
const PRIME64_2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const PRIME64_3: u64 = 0x1656_67b1_9e37_79f9;
const PRIME64_4: u64 = 0x85eb_ca77_c2b2_ae63;
const PRIME64_5: u64 = 0x27d4_eb2f_1656_67c5;

pub fn is_oauth_token(key: &str) -> bool {
    key.starts_with("sk-ant-oat")
}

pub fn is_oauth_auth(auth: &ResolvedAuth) -> bool {
    auth.headers.iter().any(|(k, v)| {
        (k.eq_ignore_ascii_case("authorization") && v.contains("sk-ant-oat"))
            || (k.eq_ignore_ascii_case("x-api-key") && v.starts_with("sk-ant-oat"))
    })
}

pub fn get_cli_version() -> String {
    if let Ok(v) = std::env::var("ANTHROPIC_CLI_VERSION") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    FALLBACK_CC_VERSION.to_string()
}

pub fn get_entrypoint() -> String {
    if let Ok(e) = std::env::var("CLAUDE_CODE_ENTRYPOINT") {
        let trimmed = e.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    CC_ENTRYPOINT.to_string()
}

pub fn build_user_agent() -> String {
    if let Ok(ua) = std::env::var("ANTHROPIC_USER_AGENT") {
        let trimmed = ua.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!(
        "claude-cli/{} (external, {})",
        get_cli_version(),
        get_entrypoint()
    )
}

fn extract_first_user_message_text(messages: &[Message]) -> String {
    for msg in messages {
        if matches!(msg.role, Role::User) {
            let mut out = String::new();
            for block in &msg.content {
                if let ContentBlock::Text { text } = block {
                    out.push_str(text);
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    String::new()
}

pub fn compute_version_suffix(message_text: &str, version: &str) -> String {
    let chars: Vec<char> = message_text.chars().collect();
    let sample_idx = [4, 7, 20];
    let mut sampled = String::with_capacity(3);
    for &i in &sample_idx {
        if i < chars.len() {
            sampled.push(chars[i]);
        } else {
            sampled.push('0');
        }
    }
    let input = format!("{BILLING_SALT}{sampled}{version}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..3].to_string()
}

pub fn build_billing_header(message_text: &str, version: &str, entrypoint: &str) -> String {
    let suffix = compute_version_suffix(message_text, version);
    format!(
        "x-anthropic-billing-header: cc_version={version}.{suffix}; cc_entrypoint={entrypoint}; cch=00000;"
    )
}

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

fn merge_round(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val))
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

pub fn xxhash64(bytes: &[u8], seed: u64) -> u64 {
    let mut offset = 0;
    let len = bytes.len();
    let mut hash: u64;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        while offset + 32 <= len {
            let lane1 = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            let lane2 = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
            let lane3 = u64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
            let lane4 = u64::from_le_bytes(bytes[offset + 24..offset + 32].try_into().unwrap());

            v1 = round(v1, lane1);
            v2 = round(v2, lane2);
            v3 = round(v3, lane3);
            v4 = round(v4, lane4);
            offset += 32;
        }

        hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        hash = merge_round(hash, v1);
        hash = merge_round(hash, v2);
        hash = merge_round(hash, v3);
        hash = merge_round(hash, v4);
    } else {
        hash = seed.wrapping_add(PRIME64_5);
    }

    hash = hash.wrapping_add(len as u64);

    while offset + 8 <= len {
        let lane = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        hash = (hash ^ round(0, lane))
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        offset += 8;
    }

    if offset + 4 <= len {
        let lane = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64;
        hash = (hash ^ lane.wrapping_mul(PRIME64_1))
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        offset += 4;
    }

    while offset < len {
        let byte = bytes[offset] as u64;
        hash = (hash ^ byte.wrapping_mul(PRIME64_5))
            .rotate_left(11)
            .wrapping_mul(PRIME64_1);
        offset += 1;
    }

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME64_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME64_3);
    hash ^= hash >> 32;

    hash
}

pub fn patch_cch(body: &mut Value) {
    let billing_text = {
        let Some(system_arr) = body.get("system").and_then(|s| s.as_array()) else {
            return;
        };
        if system_arr.is_empty() {
            return;
        }
        let Some(text) = system_arr[0].get("text").and_then(|t| t.as_str()) else {
            return;
        };
        if !text.contains("cch=00000") {
            return;
        }
        text.to_string()
    };

    let mut normalized = body.clone();
    normalized["model"] = json!("");
    if let Some(obj) = normalized.as_object_mut() {
        obj.remove("max_tokens");
    }
    let serialized = serde_json::to_vec(&normalized).unwrap_or_default();
    let hash = xxhash64(&serialized, CCH_SEED);
    let cch = format!("{:05x}", hash & 0xfffff);

    let new_billing_text = billing_text.replace("cch=00000", &format!("cch={cch}"));
    if let Some(system_arr) = body.get_mut("system").and_then(|s| s.as_array_mut())
        && !system_arr.is_empty()
    {
        system_arr[0]["text"] = json!(new_billing_text);
    }
}

pub fn transform_for_oauth(
    body: &mut Value,
    original_system_blocks: &[SystemBlock<'_>],
    messages: &[Message],
) {
    let first_user_text = extract_first_user_message_text(messages);
    let version = get_cli_version();
    let entrypoint = get_entrypoint();
    let billing_header = build_billing_header(&first_user_text, &version, &entrypoint);

    body["system"] = json!([
        {
            "type": "text",
            "text": billing_header,
        },
        {
            "type": "text",
            "text": AGENT_SDK_IDENTITY,
            "cache_control": {
                "type": "ephemeral"
            }
        }
    ]);

    let mut system_text = String::new();
    for sb in original_system_blocks {
        if !sb.text.is_empty() {
            if !system_text.is_empty() {
                system_text.push_str("\n\n");
            }
            system_text.push_str(sb.text);
        }
    }

    if !system_text.is_empty()
        && let Some(messages_arr) = body.get_mut("messages").and_then(|m| m.as_array_mut())
        && let Some(first_user) = messages_arr
            .iter_mut()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
    {
        let prefix_block = json!({
            "type": "text",
            "text": system_text,
            "cache_control": {
                "type": "ephemeral"
            }
        });

        match first_user.get_mut("content") {
            Some(Value::String(s)) => {
                let original_str = s.clone();
                first_user["content"] = json!([
                    prefix_block,
                    {
                        "type": "text",
                        "text": original_str,
                    }
                ]);
            }
            Some(Value::Array(arr)) => {
                arr.insert(0, prefix_block);
            }
            _ => {}
        }
    }

    patch_cch(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxhash64_empty() {
        assert_eq!(xxhash64(b"", 0), 0xef46db3751d8e999);
    }

    #[test]
    fn xxhash64_test_bytes() {
        assert_eq!(xxhash64(b"test", 0), 0x4fdcca5ddb678139);
    }

    #[test]
    fn is_oauth_detection() {
        assert!(is_oauth_token("sk-ant-oat01-test"));
        assert!(!is_oauth_token("sk-ant-api03-test"));

        let auth_bearer = ResolvedAuth {
            base_url: None,
            headers: vec![("authorization".into(), "Bearer sk-ant-oat01-test".into())],
        };
        assert!(is_oauth_auth(&auth_bearer));

        let auth_api_key = ResolvedAuth {
            base_url: None,
            headers: vec![("x-api-key".into(), "sk-ant-api03-test".into())],
        };
        assert!(!is_oauth_auth(&auth_api_key));
    }

    #[test]
    fn version_suffix_deterministic() {
        let suffix1 = compute_version_suffix("hello world from user prompt", "2.1.224");
        let suffix2 = compute_version_suffix("hello world from user prompt", "2.1.224");
        assert_eq!(suffix1, suffix2);
        assert_eq!(suffix1.len(), 3);
    }

    #[test]
    fn oauth_payload_transformation() {
        let mut body = json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 8000,
            "messages": [
                {
                    "role": "user",
                    "content": "Hello Claude"
                }
            ]
        });
        let system_blocks = vec![SystemBlock {
            r#type: "text",
            text: "You are a coding assistant.",
            cache_control: None,
        }];
        let messages = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Hello Claude".into(),
            }],
            ..Default::default()
        }];

        transform_for_oauth(&mut body, &system_blocks, &messages);

        let system = body["system"].as_array().expect("system should be array");
        assert_eq!(system.len(), 2);
        let header_str = system[0]["text"].as_str().unwrap();
        assert!(header_str.starts_with("x-anthropic-billing-header: cc_version="));
        assert!(header_str.contains("cc_entrypoint=sdk-cli;"));
        assert!(
            !header_str.contains("cch=00000;"),
            "placeholder must be patched with real cch"
        );
        assert_eq!(system[1]["text"], AGENT_SDK_IDENTITY);

        let msgs = body["messages"]
            .as_array()
            .expect("messages should be array");
        let first_user_content = msgs[0]["content"].as_array().expect("content array");
        assert_eq!(first_user_content[0]["text"], "You are a coding assistant.");
        assert_eq!(first_user_content[1]["text"], "Hello Claude");
    }
}
