//! Derive stable audit-evidence identifiers from resource names.
//!
//! These produce `anon-cvx-{hex}` or original sandbox IDs for audit
//! tracking. They do not need to reverse back to the actual sandbox ID;
//! classification is handled by matching against [`ExpectedResources`].

use super::expected::PREFIX_NFT_TABLE;

/// Derive a sandbox identity from a link name.
pub(super) fn derive_sandbox_id_from_link(name: &str) -> Option<String> {
    let hex_part = name
        .strip_prefix("hp-cvx")
        .or_else(|| name.strip_prefix("cvx"))
        .or_else(|| name.strip_prefix("hpc"))?;

    if hex_part.len() != 10 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(format!("anon-cvx-{hex_part}"))
}

/// Derive a sandbox identity from a namespace name.
pub(super) fn derive_sandbox_id_from_ns(name: &str) -> Option<String> {
    let hex_part = name
        .strip_prefix("cnt-cvx")
        .or_else(|| name.strip_prefix("cvx"))?;

    if hex_part.len() != 10 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(format!("anon-cvx-{hex_part}"))
}

/// Derive a sandbox identity from an nftables table name.
pub(super) fn derive_sandbox_id_from_nft_table(table_name: &str) -> Option<String> {
    let rest = table_name.strip_prefix(PREFIX_NFT_TABLE)?;
    if let Some(pos) = rest
        .rfind("-cvx")
        .or_else(|| rest.rfind("-hpc"))
        .or_else(|| rest.rfind("-hp-"))
    {
        return Some(rest[..pos].to_string());
    }
    None
}
