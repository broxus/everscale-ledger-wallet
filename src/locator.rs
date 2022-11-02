use {
    ed25519_dalek::PublicKey,
    std::{
        convert::{Infallible, TryFrom},
        str::FromStr,
    },
    thiserror::Error,
    uriparse::URIReferenceError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manufacturer {
    Unknown,
    Ledger,
}

impl Default for Manufacturer {
    fn default() -> Self {
        Self::Unknown
    }
}

const MANUFACTURER_UNKNOWN: &str = "unknown";
const MANUFACTURER_LEDGER: &str = "ledger";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("not a manufacturer")]
pub struct ManufacturerError;

impl From<Infallible> for ManufacturerError {
    fn from(_: Infallible) -> Self {
        ManufacturerError
    }
}

impl FromStr for Manufacturer {
    type Err = ManufacturerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        match s.as_str() {
            MANUFACTURER_LEDGER => Ok(Self::Ledger),
            _ => Err(ManufacturerError),
        }
    }
}

impl TryFrom<&str> for Manufacturer {
    type Error = ManufacturerError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Manufacturer::from_str(s)
    }
}

impl AsRef<str> for Manufacturer {
    fn as_ref(&self) -> &str {
        match self {
            Self::Unknown => MANUFACTURER_UNKNOWN,
            Self::Ledger => MANUFACTURER_LEDGER,
        }
    }
}

impl std::fmt::Display for Manufacturer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s: &str = self.as_ref();
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocatorError {
    #[error(transparent)]
    ManufacturerError(#[from] ManufacturerError),
    #[error(transparent)]
    UriReferenceError(#[from] URIReferenceError),
    #[error("unimplemented scheme")]
    UnimplementedScheme,
    #[error("infallible")]
    Infallible,
}

impl From<Infallible> for LocatorError {
    fn from(_: Infallible) -> Self {
        Self::Infallible
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Locator {
    pub manufacturer: Manufacturer,
    pub pubkey: Option<PublicKey>,
}
