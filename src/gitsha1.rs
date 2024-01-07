use anyhow::bail;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GitSha1(String);

impl AsRef<str> for GitSha1 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for GitSha1 {
    type Error = anyhow::Error;
    fn try_from(val: &str) -> anyhow::Result<Self> {
        const SHA1_LEN: usize = 40;
        if val.len() != SHA1_LEN {
            bail!("Unexpected length for sha1: {}", val.len());
        }
        let is_alphanumeric = val.chars().all(|c| c.is_alphanumeric());
        if !is_alphanumeric {
            bail!("value is not alphanumeric: {}", val);
        }

        Ok(GitSha1(val.to_string()))
    }
}

impl TryFrom<String> for GitSha1 {
    type Error = anyhow::Error;
    fn try_from(val: String) -> anyhow::Result<Self> {
        const SHA1_LEN: usize = 40;
        if val.len() != SHA1_LEN {
            bail!("Unexpected length for sha1: {}", val.len());
        }
        let is_alphanumeric = val.chars().all(|c| c.is_alphanumeric());
        if !is_alphanumeric {
            bail!("value is not alphanumeric: {}", val);
        }

        Ok(GitSha1(val))
    }
}
