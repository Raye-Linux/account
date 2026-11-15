//! How this PC shows up in "Your devices".

use std::fs;

pub struct DeviceInfo {
    pub name: String,
    pub model: String,
    pub raye_version: String,
}

fn first_line(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()?.lines().next().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty())
}

fn key_value(path: &str, key: &str) -> Option<String> {
    fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix('=')?;
        Some(v.trim().trim_matches('"').to_owned()).filter(|v| !v.is_empty())
    })
}

/// Firmware fills these with all sorts of filler; none of it is a name.
fn junk(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["to be filled", "default string", "system product name", "system manufacturer", "not specified", "o.e.m.", "none"]
        .iter()
        .any(|j| l.contains(j))
}

pub fn model_from(vendor: Option<String>, product: Option<String>) -> String {
    let vendor = vendor.filter(|v| !junk(v));
    let product = product.filter(|p| !junk(p));
    match (vendor, product) {
        (Some(v), Some(p)) if p.to_ascii_lowercase().starts_with(&v.to_ascii_lowercase()) => p,
        (Some(v), Some(p)) => {
            // "Dell Inc." reads better as "Dell".
            let v = v.trim_end_matches(" Inc.").trim_end_matches(" Inc").trim_end_matches(',');
            format!("{v} {p}")
        }
        (None, Some(p)) => p,
        (Some(v), None) => v,
        (None, None) => "PC".into(),
    }
}

pub fn current() -> DeviceInfo {
    // RAYE_ACCOUNT_DEVICE_NAME lets a test run two "PCs" on one machine.
    let name = std::env::var("RAYE_ACCOUNT_DEVICE_NAME")
        .ok()
        .filter(|n| !n.trim().is_empty())
        .or_else(|| key_value("/etc/machine-info", "PRETTY_HOSTNAME"))
        .or_else(|| first_line("/etc/hostname"))
        .unwrap_or_else(|| "Raye PC".into());
    let model = model_from(
        first_line("/sys/class/dmi/id/sys_vendor"),
        first_line("/sys/class/dmi/id/product_name"),
    );
    let raye_version = key_value("/etc/os-release", "VERSION_ID").unwrap_or_else(|| "0".into());
    DeviceInfo {
        name: name.chars().take(64).collect(),
        model: model.chars().take(96).collect(),
        raye_version: raye_version.chars().take(32).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn models() {
        let s = |x: &str| Some(x.to_owned());
        assert_eq!(model_from(s("Dell Inc."), s("Latitude 5420")), "Dell Latitude 5420");
        assert_eq!(model_from(s("LENOVO"), s("LENOVO ThinkPad")), "LENOVO ThinkPad");
        assert_eq!(model_from(s("To Be Filled By O.E.M."), s("Default string")), "PC");
        assert_eq!(model_from(s("QEMU"), s("Standard PC (Q35 + ICH9, 2009)")), "QEMU Standard PC (Q35 + ICH9, 2009)");
        assert_eq!(model_from(None, s("MS-7C91")), "MS-7C91");
    }
}
