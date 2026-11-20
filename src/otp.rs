//! TOTP settings, from the three attribute layouts KeePass tools store, to one `otpauth://` URI.
//!
//! | Format | Attributes |
//! | --- | --- |
//! | [`OtpFormat::OtpauthUri`] | `otp` = an `otpauth://` URI (KeePassXC 2.6+) |
//! | [`OtpFormat::KeePassXcLegacy`] | `TOTP Seed`, optional `TOTP Settings` = `period;digits` or `period;S` (Steam) |
//! | [`OtpFormat::KeePass2`] | `TimeOtp-Secret-Base32`, optional `TimeOtp-Period`, `TimeOtp-Length`, `TimeOtp-Algorithm` |
//!
//! When an entry carries more than one layout, the first in that table wins. The winning layout's
//! attributes are consumed: they become the entry's TOTP and are not also custom attributes. A
//! losing layout's attributes, and the attributes of a layout that fails to parse, stay custom
//! attributes, so nothing is dropped.

use std::num::NonZeroU32;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

use crate::model::CustomAttributes;
use crate::secret::SecretBytes;

/// An entry's TOTP: `T` is [`TotpSource`] as imported and [`OtpUri`] once resolved.
#[derive(Clone, Debug)]
pub enum Otp<T> {
    Absent,
    Present(T),
    /// The entry has TOTP attributes this tool cannot read; they stay custom attributes.
    Unrecognised(OtpIssue),
}

impl<T> Otp<T> {
    pub(crate) fn map_present<U>(&self, render: impl FnOnce(&T) -> U) -> Otp<U> {
        match self {
            Self::Absent => Otp::Absent,
            Self::Present(value) => Otp::Present(render(value)),
            Self::Unrecognised(issue) => Otp::Unrecognised(*issue),
        }
    }
}

/// Which attribute layout an entry's TOTP came in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpFormat {
    OtpauthUri,
    KeePassXcLegacy,
    KeePass2,
}

impl OtpFormat {
    const BY_PRECEDENCE: [Self; 3] = [Self::OtpauthUri, Self::KeePassXcLegacy, Self::KeePass2];

    /// The attribute whose presence says the entry uses this layout.
    fn primary_key(self) -> &'static str {
        match self {
            Self::OtpauthUri => URI_KEY,
            Self::KeePassXcLegacy => LEGACY_SEED_KEY,
            Self::KeePass2 => KEEPASS2_SECRET_KEY,
        }
    }

    fn source_keys(self) -> &'static [&'static str] {
        match self {
            Self::OtpauthUri => &[URI_KEY],
            Self::KeePassXcLegacy => &[LEGACY_SEED_KEY, LEGACY_SETTINGS_KEY],
            Self::KeePass2 => &[
                KEEPASS2_SECRET_KEY,
                KEEPASS2_PERIOD_KEY,
                KEEPASS2_LENGTH_KEY,
                KEEPASS2_ALGORITHM_KEY,
            ],
        }
    }
}

const URI_KEY: &str = "otp";
const LEGACY_SEED_KEY: &str = "TOTP Seed";
const LEGACY_SETTINGS_KEY: &str = "TOTP Settings";
const KEEPASS2_SECRET_KEY: &str = "TimeOtp-Secret-Base32";
const KEEPASS2_PERIOD_KEY: &str = "TimeOtp-Period";
const KEEPASS2_LENGTH_KEY: &str = "TimeOtp-Length";
const KEEPASS2_ALGORITHM_KEY: &str = "TimeOtp-Algorithm";

/// Why an entry's TOTP attributes could not be read. Never carries attribute values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtpIssue {
    pub format: OtpFormat,
    pub problem: OtpProblem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpProblem {
    NotAnOtpauthUri,
    EmptySecret,
    /// `TOTP Settings` is not `period;digits` or `period;S`.
    InvalidSettings,
    InvalidPeriod,
    InvalidDigits,
    UnknownAlgorithm,
}

/// TOTP as stored on an entry, parsed but not yet rendered.
#[derive(Clone, Debug)]
pub enum TotpSource {
    /// The `otp` attribute, kept byte-exact.
    Uri(OtpUri),
    Params(TotpParams),
}

/// Opaque outside this module: the rest of the tool sees TOTP only as the rendered [`OtpUri`].
#[derive(Clone, Debug)]
pub struct TotpParams {
    /// Base32, as the entry stores it.
    secret: SecretBytes,
    period_seconds: NonZeroU32,
    kind: TotpKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TotpKind {
    Standard {
        digits: Digits,
        algorithm: Algorithm,
    },
    /// Steam Guard: five characters from Steam's alphabet, HMAC-SHA-1.
    Steam,
}

/// Code length, 6 to 8 digits: the range KeePassXC offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Digits(u8);

impl Digits {
    const DEFAULT: Self = Self(6);

    fn parse(text: &str) -> Option<Self> {
        let count: u8 = text.parse().ok()?;
        (6..=8).contains(&count).then_some(Self(count))
    }

    fn count(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// An `otpauth://` URI: the one TOTP form the rest of the tool sees.
#[derive(Clone, Debug)]
pub struct OtpUri(SecretBytes);

impl OtpUri {
    const SCHEME: &'static [u8] = b"otpauth://";

    fn parse(value: &SecretBytes) -> Option<Self> {
        let scheme = value.expose().get(..Self::SCHEME.len())?;
        scheme
            .eq_ignore_ascii_case(Self::SCHEME)
            .then(|| Self(value.clone()))
    }

    #[must_use]
    pub fn as_secret(&self) -> &SecretBytes {
        &self.0
    }
}

const DEFAULT_PERIOD_SECONDS: NonZeroU32 = NonZeroU32::new(30).unwrap();

/// Finds the entry's TOTP among its custom attributes, removing the attributes it consumed.
pub(crate) fn extract(custom: &mut CustomAttributes) -> Otp<TotpSource> {
    let Some((format, primary)) = OtpFormat::BY_PRECEDENCE.into_iter().find_map(|format| {
        custom
            .get(format.primary_key())
            .map(|value| (format, value))
    }) else {
        return Otp::Absent;
    };
    match parse(format, primary, custom) {
        Ok(source) => {
            for key in format.source_keys() {
                custom.remove(*key);
            }
            Otp::Present(source)
        }
        Err(problem) => Otp::Unrecognised(OtpIssue { format, problem }),
    }
}

fn parse(
    format: OtpFormat,
    primary: &SecretBytes,
    custom: &CustomAttributes,
) -> Result<TotpSource, OtpProblem> {
    let text = |key: &str| custom.get(key).map(|value| utf8(value.expose()));
    match format {
        OtpFormat::OtpauthUri => OtpUri::parse(primary)
            .map(TotpSource::Uri)
            .ok_or(OtpProblem::NotAnOtpauthUri),
        OtpFormat::KeePassXcLegacy => {
            let (period_seconds, kind) = match text(LEGACY_SETTINGS_KEY) {
                None => (DEFAULT_PERIOD_SECONDS, TotpKind::standard_default()),
                Some(settings) => parse_legacy_settings(settings?)?,
            };
            params(primary, period_seconds, kind)
        }
        OtpFormat::KeePass2 => {
            let period_seconds = match text(KEEPASS2_PERIOD_KEY) {
                None => DEFAULT_PERIOD_SECONDS,
                Some(period) => parse_period(period?)?,
            };
            let digits = match text(KEEPASS2_LENGTH_KEY) {
                None => Digits::DEFAULT,
                Some(length) => Digits::parse(length?).ok_or(OtpProblem::InvalidDigits)?,
            };
            let algorithm = match text(KEEPASS2_ALGORITHM_KEY) {
                None => Algorithm::Sha1,
                Some(name) => parse_keepass2_algorithm(name?)?,
            };
            params(
                primary,
                period_seconds,
                TotpKind::Standard { digits, algorithm },
            )
        }
    }
}

impl TotpKind {
    fn standard_default() -> Self {
        Self::Standard {
            digits: Digits::DEFAULT,
            algorithm: Algorithm::Sha1,
        }
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, OtpProblem> {
    std::str::from_utf8(bytes).map_err(|_| OtpProblem::InvalidSettings)
}

fn params(
    secret: &SecretBytes,
    period_seconds: NonZeroU32,
    kind: TotpKind,
) -> Result<TotpSource, OtpProblem> {
    if secret.is_empty() {
        return Err(OtpProblem::EmptySecret);
    }
    Ok(TotpSource::Params(TotpParams {
        secret: secret.clone(),
        period_seconds,
        kind,
    }))
}

fn parse_legacy_settings(settings: &str) -> Result<(NonZeroU32, TotpKind), OtpProblem> {
    let (period, digits) = settings
        .split_once(';')
        .ok_or(OtpProblem::InvalidSettings)?;
    let kind = match digits {
        "S" => TotpKind::Steam,
        count => TotpKind::Standard {
            digits: Digits::parse(count).ok_or(OtpProblem::InvalidDigits)?,
            algorithm: Algorithm::Sha1,
        },
    };
    Ok((parse_period(period)?, kind))
}

fn parse_period(text: &str) -> Result<NonZeroU32, OtpProblem> {
    text.parse().map_err(|_| OtpProblem::InvalidPeriod)
}

fn parse_keepass2_algorithm(name: &str) -> Result<Algorithm, OtpProblem> {
    match name {
        "HMAC-SHA-1" => Ok(Algorithm::Sha1),
        "HMAC-SHA-256" => Ok(Algorithm::Sha256),
        "HMAC-SHA-512" => Ok(Algorithm::Sha512),
        _ => Err(OtpProblem::UnknownAlgorithm),
    }
}

/// RFC 3986 unreserved characters pass through; everything else is percent-encoded.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Encodes piece by piece into `uri`, so no intermediate `String` holds the secret.
fn push_percent_encoded(uri: &mut SecretBytes, bytes: &[u8]) {
    percent_encode(bytes, URI_COMPONENT).for_each(|piece| uri.extend_from_slice(piece.as_bytes()));
}

impl TotpSource {
    /// The URI for this TOTP. Parameters render in KeePassXC's own layout,
    /// `otpauth://totp/<title>:<username>?secret=…&period=…&digits=…&issuer=<title>`, plus the
    /// algorithm always and `encoder=steam` for Steam; an absent title or username renders empty.
    pub(crate) fn render(
        &self,
        title: Option<&SecretBytes>,
        user_name: Option<&SecretBytes>,
    ) -> OtpUri {
        match self {
            Self::Uri(uri) => uri.clone(),
            Self::Params(params) => OtpUri(params.render(title, user_name)),
        }
    }
}

impl TotpParams {
    fn render(&self, title: Option<&SecretBytes>, user_name: Option<&SecretBytes>) -> SecretBytes {
        let title = title.map_or(&b""[..], SecretBytes::expose);
        let user_name = user_name.map_or(&b""[..], SecretBytes::expose);
        let (digits, algorithm, encoder) = match self.kind {
            TotpKind::Standard { digits, algorithm } => (digits.count(), algorithm, None),
            TotpKind::Steam => (5, Algorithm::Sha1, Some("steam")),
        };
        let mut uri = SecretBytes::new();
        uri.extend_from_slice(b"otpauth://totp/");
        push_percent_encoded(&mut uri, title);
        uri.extend_from_slice(b":");
        push_percent_encoded(&mut uri, user_name);
        uri.extend_from_slice(b"?secret=");
        push_percent_encoded(&mut uri, self.secret.expose());
        let fixed = format!("&period={}&digits={digits}&issuer=", self.period_seconds);
        uri.extend_from_slice(fixed.as_bytes());
        push_percent_encoded(&mut uri, title);
        uri.extend_from_slice(b"&algorithm=");
        uri.extend_from_slice(algorithm.uri_name().as_bytes());
        if let Some(encoder) = encoder {
            uri.extend_from_slice(b"&encoder=");
            uri.extend_from_slice(encoder.as_bytes());
        }
        uri
    }
}
