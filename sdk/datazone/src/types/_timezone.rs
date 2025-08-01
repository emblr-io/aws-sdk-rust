// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Timezone`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let timezone = unimplemented!();
/// match timezone {
///     Timezone::AfricaJohannesburg => { /* ... */ },
///     Timezone::AmericaMontreal => { /* ... */ },
///     Timezone::AmericaSaoPaulo => { /* ... */ },
///     Timezone::AsiaBahrain => { /* ... */ },
///     Timezone::AsiaBangkok => { /* ... */ },
///     Timezone::AsiaCalcutta => { /* ... */ },
///     Timezone::AsiaDubai => { /* ... */ },
///     Timezone::AsiaHongKong => { /* ... */ },
///     Timezone::AsiaJakarta => { /* ... */ },
///     Timezone::AsiaKualaLumpur => { /* ... */ },
///     Timezone::AsiaSeoul => { /* ... */ },
///     Timezone::AsiaShanghai => { /* ... */ },
///     Timezone::AsiaSingapore => { /* ... */ },
///     Timezone::AsiaTaipei => { /* ... */ },
///     Timezone::AsiaTokyo => { /* ... */ },
///     Timezone::AustraliaMelbourne => { /* ... */ },
///     Timezone::AustraliaSydney => { /* ... */ },
///     Timezone::CanadaCentral => { /* ... */ },
///     Timezone::Cet => { /* ... */ },
///     Timezone::Cst6Cdt => { /* ... */ },
///     Timezone::EtcGmt => { /* ... */ },
///     Timezone::EtcGmt0 => { /* ... */ },
///     Timezone::EtcGmtAdd0 => { /* ... */ },
///     Timezone::EtcGmtAdd1 => { /* ... */ },
///     Timezone::EtcGmtAdd10 => { /* ... */ },
///     Timezone::EtcGmtAdd11 => { /* ... */ },
///     Timezone::EtcGmtAdd12 => { /* ... */ },
///     Timezone::EtcGmtAdd2 => { /* ... */ },
///     Timezone::EtcGmtAdd3 => { /* ... */ },
///     Timezone::EtcGmtAdd4 => { /* ... */ },
///     Timezone::EtcGmtAdd5 => { /* ... */ },
///     Timezone::EtcGmtAdd6 => { /* ... */ },
///     Timezone::EtcGmtAdd7 => { /* ... */ },
///     Timezone::EtcGmtAdd8 => { /* ... */ },
///     Timezone::EtcGmtAdd9 => { /* ... */ },
///     Timezone::EtcGmtNeg0 => { /* ... */ },
///     Timezone::EtcGmtNeg1 => { /* ... */ },
///     Timezone::EtcGmtNeg10 => { /* ... */ },
///     Timezone::EtcGmtNeg11 => { /* ... */ },
///     Timezone::EtcGmtNeg12 => { /* ... */ },
///     Timezone::EtcGmtNeg13 => { /* ... */ },
///     Timezone::EtcGmtNeg14 => { /* ... */ },
///     Timezone::EtcGmtNeg2 => { /* ... */ },
///     Timezone::EtcGmtNeg3 => { /* ... */ },
///     Timezone::EtcGmtNeg4 => { /* ... */ },
///     Timezone::EtcGmtNeg5 => { /* ... */ },
///     Timezone::EtcGmtNeg6 => { /* ... */ },
///     Timezone::EtcGmtNeg7 => { /* ... */ },
///     Timezone::EtcGmtNeg8 => { /* ... */ },
///     Timezone::EtcGmtNeg9 => { /* ... */ },
///     Timezone::EuropeDublin => { /* ... */ },
///     Timezone::EuropeLondon => { /* ... */ },
///     Timezone::EuropeParis => { /* ... */ },
///     Timezone::EuropeStockholm => { /* ... */ },
///     Timezone::EuropeZurich => { /* ... */ },
///     Timezone::Israel => { /* ... */ },
///     Timezone::MexicoGeneral => { /* ... */ },
///     Timezone::Mst7Mdt => { /* ... */ },
///     Timezone::PacificAuckland => { /* ... */ },
///     Timezone::UsCentral => { /* ... */ },
///     Timezone::UsEastern => { /* ... */ },
///     Timezone::UsMountain => { /* ... */ },
///     Timezone::UsPacific => { /* ... */ },
///     Timezone::Utc => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `timezone` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Timezone::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Timezone::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Timezone::NewFeature` is defined.
/// Specifically, when `timezone` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Timezone::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum Timezone {
    #[allow(missing_docs)] // documentation missing in model
    AfricaJohannesburg,
    #[allow(missing_docs)] // documentation missing in model
    AmericaMontreal,
    #[allow(missing_docs)] // documentation missing in model
    AmericaSaoPaulo,
    #[allow(missing_docs)] // documentation missing in model
    AsiaBahrain,
    #[allow(missing_docs)] // documentation missing in model
    AsiaBangkok,
    #[allow(missing_docs)] // documentation missing in model
    AsiaCalcutta,
    #[allow(missing_docs)] // documentation missing in model
    AsiaDubai,
    #[allow(missing_docs)] // documentation missing in model
    AsiaHongKong,
    #[allow(missing_docs)] // documentation missing in model
    AsiaJakarta,
    #[allow(missing_docs)] // documentation missing in model
    AsiaKualaLumpur,
    #[allow(missing_docs)] // documentation missing in model
    AsiaSeoul,
    #[allow(missing_docs)] // documentation missing in model
    AsiaShanghai,
    #[allow(missing_docs)] // documentation missing in model
    AsiaSingapore,
    #[allow(missing_docs)] // documentation missing in model
    AsiaTaipei,
    #[allow(missing_docs)] // documentation missing in model
    AsiaTokyo,
    #[allow(missing_docs)] // documentation missing in model
    AustraliaMelbourne,
    #[allow(missing_docs)] // documentation missing in model
    AustraliaSydney,
    #[allow(missing_docs)] // documentation missing in model
    CanadaCentral,
    #[allow(missing_docs)] // documentation missing in model
    Cet,
    #[allow(missing_docs)] // documentation missing in model
    Cst6Cdt,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmt,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmt0,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd0,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd1,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd10,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd11,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd12,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd2,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd3,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd4,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd5,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd6,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd7,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd8,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtAdd9,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg0,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg1,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg10,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg11,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg12,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg13,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg14,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg2,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg3,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg4,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg5,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg6,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg7,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg8,
    #[allow(missing_docs)] // documentation missing in model
    EtcGmtNeg9,
    #[allow(missing_docs)] // documentation missing in model
    EuropeDublin,
    #[allow(missing_docs)] // documentation missing in model
    EuropeLondon,
    #[allow(missing_docs)] // documentation missing in model
    EuropeParis,
    #[allow(missing_docs)] // documentation missing in model
    EuropeStockholm,
    #[allow(missing_docs)] // documentation missing in model
    EuropeZurich,
    #[allow(missing_docs)] // documentation missing in model
    Israel,
    #[allow(missing_docs)] // documentation missing in model
    MexicoGeneral,
    #[allow(missing_docs)] // documentation missing in model
    Mst7Mdt,
    #[allow(missing_docs)] // documentation missing in model
    PacificAuckland,
    #[allow(missing_docs)] // documentation missing in model
    UsCentral,
    #[allow(missing_docs)] // documentation missing in model
    UsEastern,
    #[allow(missing_docs)] // documentation missing in model
    UsMountain,
    #[allow(missing_docs)] // documentation missing in model
    UsPacific,
    #[allow(missing_docs)] // documentation missing in model
    Utc,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Timezone {
    fn from(s: &str) -> Self {
        match s {
            "AFRICA_JOHANNESBURG" => Timezone::AfricaJohannesburg,
            "AMERICA_MONTREAL" => Timezone::AmericaMontreal,
            "AMERICA_SAO_PAULO" => Timezone::AmericaSaoPaulo,
            "ASIA_BAHRAIN" => Timezone::AsiaBahrain,
            "ASIA_BANGKOK" => Timezone::AsiaBangkok,
            "ASIA_CALCUTTA" => Timezone::AsiaCalcutta,
            "ASIA_DUBAI" => Timezone::AsiaDubai,
            "ASIA_HONG_KONG" => Timezone::AsiaHongKong,
            "ASIA_JAKARTA" => Timezone::AsiaJakarta,
            "ASIA_KUALA_LUMPUR" => Timezone::AsiaKualaLumpur,
            "ASIA_SEOUL" => Timezone::AsiaSeoul,
            "ASIA_SHANGHAI" => Timezone::AsiaShanghai,
            "ASIA_SINGAPORE" => Timezone::AsiaSingapore,
            "ASIA_TAIPEI" => Timezone::AsiaTaipei,
            "ASIA_TOKYO" => Timezone::AsiaTokyo,
            "AUSTRALIA_MELBOURNE" => Timezone::AustraliaMelbourne,
            "AUSTRALIA_SYDNEY" => Timezone::AustraliaSydney,
            "CANADA_CENTRAL" => Timezone::CanadaCentral,
            "CET" => Timezone::Cet,
            "CST6CDT" => Timezone::Cst6Cdt,
            "ETC_GMT" => Timezone::EtcGmt,
            "ETC_GMT0" => Timezone::EtcGmt0,
            "ETC_GMT_ADD_0" => Timezone::EtcGmtAdd0,
            "ETC_GMT_ADD_1" => Timezone::EtcGmtAdd1,
            "ETC_GMT_ADD_10" => Timezone::EtcGmtAdd10,
            "ETC_GMT_ADD_11" => Timezone::EtcGmtAdd11,
            "ETC_GMT_ADD_12" => Timezone::EtcGmtAdd12,
            "ETC_GMT_ADD_2" => Timezone::EtcGmtAdd2,
            "ETC_GMT_ADD_3" => Timezone::EtcGmtAdd3,
            "ETC_GMT_ADD_4" => Timezone::EtcGmtAdd4,
            "ETC_GMT_ADD_5" => Timezone::EtcGmtAdd5,
            "ETC_GMT_ADD_6" => Timezone::EtcGmtAdd6,
            "ETC_GMT_ADD_7" => Timezone::EtcGmtAdd7,
            "ETC_GMT_ADD_8" => Timezone::EtcGmtAdd8,
            "ETC_GMT_ADD_9" => Timezone::EtcGmtAdd9,
            "ETC_GMT_NEG_0" => Timezone::EtcGmtNeg0,
            "ETC_GMT_NEG_1" => Timezone::EtcGmtNeg1,
            "ETC_GMT_NEG_10" => Timezone::EtcGmtNeg10,
            "ETC_GMT_NEG_11" => Timezone::EtcGmtNeg11,
            "ETC_GMT_NEG_12" => Timezone::EtcGmtNeg12,
            "ETC_GMT_NEG_13" => Timezone::EtcGmtNeg13,
            "ETC_GMT_NEG_14" => Timezone::EtcGmtNeg14,
            "ETC_GMT_NEG_2" => Timezone::EtcGmtNeg2,
            "ETC_GMT_NEG_3" => Timezone::EtcGmtNeg3,
            "ETC_GMT_NEG_4" => Timezone::EtcGmtNeg4,
            "ETC_GMT_NEG_5" => Timezone::EtcGmtNeg5,
            "ETC_GMT_NEG_6" => Timezone::EtcGmtNeg6,
            "ETC_GMT_NEG_7" => Timezone::EtcGmtNeg7,
            "ETC_GMT_NEG_8" => Timezone::EtcGmtNeg8,
            "ETC_GMT_NEG_9" => Timezone::EtcGmtNeg9,
            "EUROPE_DUBLIN" => Timezone::EuropeDublin,
            "EUROPE_LONDON" => Timezone::EuropeLondon,
            "EUROPE_PARIS" => Timezone::EuropeParis,
            "EUROPE_STOCKHOLM" => Timezone::EuropeStockholm,
            "EUROPE_ZURICH" => Timezone::EuropeZurich,
            "ISRAEL" => Timezone::Israel,
            "MEXICO_GENERAL" => Timezone::MexicoGeneral,
            "MST7MDT" => Timezone::Mst7Mdt,
            "PACIFIC_AUCKLAND" => Timezone::PacificAuckland,
            "US_CENTRAL" => Timezone::UsCentral,
            "US_EASTERN" => Timezone::UsEastern,
            "US_MOUNTAIN" => Timezone::UsMountain,
            "US_PACIFIC" => Timezone::UsPacific,
            "UTC" => Timezone::Utc,
            other => Timezone::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Timezone {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Timezone::from(s))
    }
}
impl Timezone {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Timezone::AfricaJohannesburg => "AFRICA_JOHANNESBURG",
            Timezone::AmericaMontreal => "AMERICA_MONTREAL",
            Timezone::AmericaSaoPaulo => "AMERICA_SAO_PAULO",
            Timezone::AsiaBahrain => "ASIA_BAHRAIN",
            Timezone::AsiaBangkok => "ASIA_BANGKOK",
            Timezone::AsiaCalcutta => "ASIA_CALCUTTA",
            Timezone::AsiaDubai => "ASIA_DUBAI",
            Timezone::AsiaHongKong => "ASIA_HONG_KONG",
            Timezone::AsiaJakarta => "ASIA_JAKARTA",
            Timezone::AsiaKualaLumpur => "ASIA_KUALA_LUMPUR",
            Timezone::AsiaSeoul => "ASIA_SEOUL",
            Timezone::AsiaShanghai => "ASIA_SHANGHAI",
            Timezone::AsiaSingapore => "ASIA_SINGAPORE",
            Timezone::AsiaTaipei => "ASIA_TAIPEI",
            Timezone::AsiaTokyo => "ASIA_TOKYO",
            Timezone::AustraliaMelbourne => "AUSTRALIA_MELBOURNE",
            Timezone::AustraliaSydney => "AUSTRALIA_SYDNEY",
            Timezone::CanadaCentral => "CANADA_CENTRAL",
            Timezone::Cet => "CET",
            Timezone::Cst6Cdt => "CST6CDT",
            Timezone::EtcGmt => "ETC_GMT",
            Timezone::EtcGmt0 => "ETC_GMT0",
            Timezone::EtcGmtAdd0 => "ETC_GMT_ADD_0",
            Timezone::EtcGmtAdd1 => "ETC_GMT_ADD_1",
            Timezone::EtcGmtAdd10 => "ETC_GMT_ADD_10",
            Timezone::EtcGmtAdd11 => "ETC_GMT_ADD_11",
            Timezone::EtcGmtAdd12 => "ETC_GMT_ADD_12",
            Timezone::EtcGmtAdd2 => "ETC_GMT_ADD_2",
            Timezone::EtcGmtAdd3 => "ETC_GMT_ADD_3",
            Timezone::EtcGmtAdd4 => "ETC_GMT_ADD_4",
            Timezone::EtcGmtAdd5 => "ETC_GMT_ADD_5",
            Timezone::EtcGmtAdd6 => "ETC_GMT_ADD_6",
            Timezone::EtcGmtAdd7 => "ETC_GMT_ADD_7",
            Timezone::EtcGmtAdd8 => "ETC_GMT_ADD_8",
            Timezone::EtcGmtAdd9 => "ETC_GMT_ADD_9",
            Timezone::EtcGmtNeg0 => "ETC_GMT_NEG_0",
            Timezone::EtcGmtNeg1 => "ETC_GMT_NEG_1",
            Timezone::EtcGmtNeg10 => "ETC_GMT_NEG_10",
            Timezone::EtcGmtNeg11 => "ETC_GMT_NEG_11",
            Timezone::EtcGmtNeg12 => "ETC_GMT_NEG_12",
            Timezone::EtcGmtNeg13 => "ETC_GMT_NEG_13",
            Timezone::EtcGmtNeg14 => "ETC_GMT_NEG_14",
            Timezone::EtcGmtNeg2 => "ETC_GMT_NEG_2",
            Timezone::EtcGmtNeg3 => "ETC_GMT_NEG_3",
            Timezone::EtcGmtNeg4 => "ETC_GMT_NEG_4",
            Timezone::EtcGmtNeg5 => "ETC_GMT_NEG_5",
            Timezone::EtcGmtNeg6 => "ETC_GMT_NEG_6",
            Timezone::EtcGmtNeg7 => "ETC_GMT_NEG_7",
            Timezone::EtcGmtNeg8 => "ETC_GMT_NEG_8",
            Timezone::EtcGmtNeg9 => "ETC_GMT_NEG_9",
            Timezone::EuropeDublin => "EUROPE_DUBLIN",
            Timezone::EuropeLondon => "EUROPE_LONDON",
            Timezone::EuropeParis => "EUROPE_PARIS",
            Timezone::EuropeStockholm => "EUROPE_STOCKHOLM",
            Timezone::EuropeZurich => "EUROPE_ZURICH",
            Timezone::Israel => "ISRAEL",
            Timezone::MexicoGeneral => "MEXICO_GENERAL",
            Timezone::Mst7Mdt => "MST7MDT",
            Timezone::PacificAuckland => "PACIFIC_AUCKLAND",
            Timezone::UsCentral => "US_CENTRAL",
            Timezone::UsEastern => "US_EASTERN",
            Timezone::UsMountain => "US_MOUNTAIN",
            Timezone::UsPacific => "US_PACIFIC",
            Timezone::Utc => "UTC",
            Timezone::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AFRICA_JOHANNESBURG",
            "AMERICA_MONTREAL",
            "AMERICA_SAO_PAULO",
            "ASIA_BAHRAIN",
            "ASIA_BANGKOK",
            "ASIA_CALCUTTA",
            "ASIA_DUBAI",
            "ASIA_HONG_KONG",
            "ASIA_JAKARTA",
            "ASIA_KUALA_LUMPUR",
            "ASIA_SEOUL",
            "ASIA_SHANGHAI",
            "ASIA_SINGAPORE",
            "ASIA_TAIPEI",
            "ASIA_TOKYO",
            "AUSTRALIA_MELBOURNE",
            "AUSTRALIA_SYDNEY",
            "CANADA_CENTRAL",
            "CET",
            "CST6CDT",
            "ETC_GMT",
            "ETC_GMT0",
            "ETC_GMT_ADD_0",
            "ETC_GMT_ADD_1",
            "ETC_GMT_ADD_10",
            "ETC_GMT_ADD_11",
            "ETC_GMT_ADD_12",
            "ETC_GMT_ADD_2",
            "ETC_GMT_ADD_3",
            "ETC_GMT_ADD_4",
            "ETC_GMT_ADD_5",
            "ETC_GMT_ADD_6",
            "ETC_GMT_ADD_7",
            "ETC_GMT_ADD_8",
            "ETC_GMT_ADD_9",
            "ETC_GMT_NEG_0",
            "ETC_GMT_NEG_1",
            "ETC_GMT_NEG_10",
            "ETC_GMT_NEG_11",
            "ETC_GMT_NEG_12",
            "ETC_GMT_NEG_13",
            "ETC_GMT_NEG_14",
            "ETC_GMT_NEG_2",
            "ETC_GMT_NEG_3",
            "ETC_GMT_NEG_4",
            "ETC_GMT_NEG_5",
            "ETC_GMT_NEG_6",
            "ETC_GMT_NEG_7",
            "ETC_GMT_NEG_8",
            "ETC_GMT_NEG_9",
            "EUROPE_DUBLIN",
            "EUROPE_LONDON",
            "EUROPE_PARIS",
            "EUROPE_STOCKHOLM",
            "EUROPE_ZURICH",
            "ISRAEL",
            "MEXICO_GENERAL",
            "MST7MDT",
            "PACIFIC_AUCKLAND",
            "US_CENTRAL",
            "US_EASTERN",
            "US_MOUNTAIN",
            "US_PACIFIC",
            "UTC",
        ]
    }
}
impl ::std::convert::AsRef<str> for Timezone {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Timezone {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for Timezone {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Timezone::AfricaJohannesburg => write!(f, "AFRICA_JOHANNESBURG"),
            Timezone::AmericaMontreal => write!(f, "AMERICA_MONTREAL"),
            Timezone::AmericaSaoPaulo => write!(f, "AMERICA_SAO_PAULO"),
            Timezone::AsiaBahrain => write!(f, "ASIA_BAHRAIN"),
            Timezone::AsiaBangkok => write!(f, "ASIA_BANGKOK"),
            Timezone::AsiaCalcutta => write!(f, "ASIA_CALCUTTA"),
            Timezone::AsiaDubai => write!(f, "ASIA_DUBAI"),
            Timezone::AsiaHongKong => write!(f, "ASIA_HONG_KONG"),
            Timezone::AsiaJakarta => write!(f, "ASIA_JAKARTA"),
            Timezone::AsiaKualaLumpur => write!(f, "ASIA_KUALA_LUMPUR"),
            Timezone::AsiaSeoul => write!(f, "ASIA_SEOUL"),
            Timezone::AsiaShanghai => write!(f, "ASIA_SHANGHAI"),
            Timezone::AsiaSingapore => write!(f, "ASIA_SINGAPORE"),
            Timezone::AsiaTaipei => write!(f, "ASIA_TAIPEI"),
            Timezone::AsiaTokyo => write!(f, "ASIA_TOKYO"),
            Timezone::AustraliaMelbourne => write!(f, "AUSTRALIA_MELBOURNE"),
            Timezone::AustraliaSydney => write!(f, "AUSTRALIA_SYDNEY"),
            Timezone::CanadaCentral => write!(f, "CANADA_CENTRAL"),
            Timezone::Cet => write!(f, "CET"),
            Timezone::Cst6Cdt => write!(f, "CST6CDT"),
            Timezone::EtcGmt => write!(f, "ETC_GMT"),
            Timezone::EtcGmt0 => write!(f, "ETC_GMT0"),
            Timezone::EtcGmtAdd0 => write!(f, "ETC_GMT_ADD_0"),
            Timezone::EtcGmtAdd1 => write!(f, "ETC_GMT_ADD_1"),
            Timezone::EtcGmtAdd10 => write!(f, "ETC_GMT_ADD_10"),
            Timezone::EtcGmtAdd11 => write!(f, "ETC_GMT_ADD_11"),
            Timezone::EtcGmtAdd12 => write!(f, "ETC_GMT_ADD_12"),
            Timezone::EtcGmtAdd2 => write!(f, "ETC_GMT_ADD_2"),
            Timezone::EtcGmtAdd3 => write!(f, "ETC_GMT_ADD_3"),
            Timezone::EtcGmtAdd4 => write!(f, "ETC_GMT_ADD_4"),
            Timezone::EtcGmtAdd5 => write!(f, "ETC_GMT_ADD_5"),
            Timezone::EtcGmtAdd6 => write!(f, "ETC_GMT_ADD_6"),
            Timezone::EtcGmtAdd7 => write!(f, "ETC_GMT_ADD_7"),
            Timezone::EtcGmtAdd8 => write!(f, "ETC_GMT_ADD_8"),
            Timezone::EtcGmtAdd9 => write!(f, "ETC_GMT_ADD_9"),
            Timezone::EtcGmtNeg0 => write!(f, "ETC_GMT_NEG_0"),
            Timezone::EtcGmtNeg1 => write!(f, "ETC_GMT_NEG_1"),
            Timezone::EtcGmtNeg10 => write!(f, "ETC_GMT_NEG_10"),
            Timezone::EtcGmtNeg11 => write!(f, "ETC_GMT_NEG_11"),
            Timezone::EtcGmtNeg12 => write!(f, "ETC_GMT_NEG_12"),
            Timezone::EtcGmtNeg13 => write!(f, "ETC_GMT_NEG_13"),
            Timezone::EtcGmtNeg14 => write!(f, "ETC_GMT_NEG_14"),
            Timezone::EtcGmtNeg2 => write!(f, "ETC_GMT_NEG_2"),
            Timezone::EtcGmtNeg3 => write!(f, "ETC_GMT_NEG_3"),
            Timezone::EtcGmtNeg4 => write!(f, "ETC_GMT_NEG_4"),
            Timezone::EtcGmtNeg5 => write!(f, "ETC_GMT_NEG_5"),
            Timezone::EtcGmtNeg6 => write!(f, "ETC_GMT_NEG_6"),
            Timezone::EtcGmtNeg7 => write!(f, "ETC_GMT_NEG_7"),
            Timezone::EtcGmtNeg8 => write!(f, "ETC_GMT_NEG_8"),
            Timezone::EtcGmtNeg9 => write!(f, "ETC_GMT_NEG_9"),
            Timezone::EuropeDublin => write!(f, "EUROPE_DUBLIN"),
            Timezone::EuropeLondon => write!(f, "EUROPE_LONDON"),
            Timezone::EuropeParis => write!(f, "EUROPE_PARIS"),
            Timezone::EuropeStockholm => write!(f, "EUROPE_STOCKHOLM"),
            Timezone::EuropeZurich => write!(f, "EUROPE_ZURICH"),
            Timezone::Israel => write!(f, "ISRAEL"),
            Timezone::MexicoGeneral => write!(f, "MEXICO_GENERAL"),
            Timezone::Mst7Mdt => write!(f, "MST7MDT"),
            Timezone::PacificAuckland => write!(f, "PACIFIC_AUCKLAND"),
            Timezone::UsCentral => write!(f, "US_CENTRAL"),
            Timezone::UsEastern => write!(f, "US_EASTERN"),
            Timezone::UsMountain => write!(f, "US_MOUNTAIN"),
            Timezone::UsPacific => write!(f, "US_PACIFIC"),
            Timezone::Utc => write!(f, "UTC"),
            Timezone::Unknown(value) => write!(f, "{}", value),
        }
    }
}
