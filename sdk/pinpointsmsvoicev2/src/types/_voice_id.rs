// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `VoiceId`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let voiceid = unimplemented!();
/// match voiceid {
///     VoiceId::Amy => { /* ... */ },
///     VoiceId::Astrid => { /* ... */ },
///     VoiceId::Bianca => { /* ... */ },
///     VoiceId::Brian => { /* ... */ },
///     VoiceId::Camila => { /* ... */ },
///     VoiceId::Carla => { /* ... */ },
///     VoiceId::Carmen => { /* ... */ },
///     VoiceId::Celine => { /* ... */ },
///     VoiceId::Chantal => { /* ... */ },
///     VoiceId::Conchita => { /* ... */ },
///     VoiceId::Cristiano => { /* ... */ },
///     VoiceId::Dora => { /* ... */ },
///     VoiceId::Emma => { /* ... */ },
///     VoiceId::Enrique => { /* ... */ },
///     VoiceId::Ewa => { /* ... */ },
///     VoiceId::Filiz => { /* ... */ },
///     VoiceId::Geraint => { /* ... */ },
///     VoiceId::Giorgio => { /* ... */ },
///     VoiceId::Gwyneth => { /* ... */ },
///     VoiceId::Hans => { /* ... */ },
///     VoiceId::Ines => { /* ... */ },
///     VoiceId::Ivy => { /* ... */ },
///     VoiceId::Jacek => { /* ... */ },
///     VoiceId::Jan => { /* ... */ },
///     VoiceId::Joanna => { /* ... */ },
///     VoiceId::Joey => { /* ... */ },
///     VoiceId::Justin => { /* ... */ },
///     VoiceId::Karl => { /* ... */ },
///     VoiceId::Kendra => { /* ... */ },
///     VoiceId::Kimberly => { /* ... */ },
///     VoiceId::Lea => { /* ... */ },
///     VoiceId::Liv => { /* ... */ },
///     VoiceId::Lotte => { /* ... */ },
///     VoiceId::Lucia => { /* ... */ },
///     VoiceId::Lupe => { /* ... */ },
///     VoiceId::Mads => { /* ... */ },
///     VoiceId::Maja => { /* ... */ },
///     VoiceId::Marlene => { /* ... */ },
///     VoiceId::Mathieu => { /* ... */ },
///     VoiceId::Matthew => { /* ... */ },
///     VoiceId::Maxim => { /* ... */ },
///     VoiceId::Mia => { /* ... */ },
///     VoiceId::Miguel => { /* ... */ },
///     VoiceId::Mizuki => { /* ... */ },
///     VoiceId::Naja => { /* ... */ },
///     VoiceId::Nicole => { /* ... */ },
///     VoiceId::Penelope => { /* ... */ },
///     VoiceId::Raveena => { /* ... */ },
///     VoiceId::Ricardo => { /* ... */ },
///     VoiceId::Ruben => { /* ... */ },
///     VoiceId::Russell => { /* ... */ },
///     VoiceId::Salli => { /* ... */ },
///     VoiceId::Seoyeon => { /* ... */ },
///     VoiceId::Takumi => { /* ... */ },
///     VoiceId::Tatyana => { /* ... */ },
///     VoiceId::Vicki => { /* ... */ },
///     VoiceId::Vitoria => { /* ... */ },
///     VoiceId::Zeina => { /* ... */ },
///     VoiceId::Zhiyu => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `voiceid` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `VoiceId::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `VoiceId::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `VoiceId::NewFeature` is defined.
/// Specifically, when `voiceid` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `VoiceId::NewFeature` also yielding `"NewFeature"`.
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
pub enum VoiceId {
    #[allow(missing_docs)] // documentation missing in model
    Amy,
    #[allow(missing_docs)] // documentation missing in model
    Astrid,
    #[allow(missing_docs)] // documentation missing in model
    Bianca,
    #[allow(missing_docs)] // documentation missing in model
    Brian,
    #[allow(missing_docs)] // documentation missing in model
    Camila,
    #[allow(missing_docs)] // documentation missing in model
    Carla,
    #[allow(missing_docs)] // documentation missing in model
    Carmen,
    #[allow(missing_docs)] // documentation missing in model
    Celine,
    #[allow(missing_docs)] // documentation missing in model
    Chantal,
    #[allow(missing_docs)] // documentation missing in model
    Conchita,
    #[allow(missing_docs)] // documentation missing in model
    Cristiano,
    #[allow(missing_docs)] // documentation missing in model
    Dora,
    #[allow(missing_docs)] // documentation missing in model
    Emma,
    #[allow(missing_docs)] // documentation missing in model
    Enrique,
    #[allow(missing_docs)] // documentation missing in model
    Ewa,
    #[allow(missing_docs)] // documentation missing in model
    Filiz,
    #[allow(missing_docs)] // documentation missing in model
    Geraint,
    #[allow(missing_docs)] // documentation missing in model
    Giorgio,
    #[allow(missing_docs)] // documentation missing in model
    Gwyneth,
    #[allow(missing_docs)] // documentation missing in model
    Hans,
    #[allow(missing_docs)] // documentation missing in model
    Ines,
    #[allow(missing_docs)] // documentation missing in model
    Ivy,
    #[allow(missing_docs)] // documentation missing in model
    Jacek,
    #[allow(missing_docs)] // documentation missing in model
    Jan,
    #[allow(missing_docs)] // documentation missing in model
    Joanna,
    #[allow(missing_docs)] // documentation missing in model
    Joey,
    #[allow(missing_docs)] // documentation missing in model
    Justin,
    #[allow(missing_docs)] // documentation missing in model
    Karl,
    #[allow(missing_docs)] // documentation missing in model
    Kendra,
    #[allow(missing_docs)] // documentation missing in model
    Kimberly,
    #[allow(missing_docs)] // documentation missing in model
    Lea,
    #[allow(missing_docs)] // documentation missing in model
    Liv,
    #[allow(missing_docs)] // documentation missing in model
    Lotte,
    #[allow(missing_docs)] // documentation missing in model
    Lucia,
    #[allow(missing_docs)] // documentation missing in model
    Lupe,
    #[allow(missing_docs)] // documentation missing in model
    Mads,
    #[allow(missing_docs)] // documentation missing in model
    Maja,
    #[allow(missing_docs)] // documentation missing in model
    Marlene,
    #[allow(missing_docs)] // documentation missing in model
    Mathieu,
    #[allow(missing_docs)] // documentation missing in model
    Matthew,
    #[allow(missing_docs)] // documentation missing in model
    Maxim,
    #[allow(missing_docs)] // documentation missing in model
    Mia,
    #[allow(missing_docs)] // documentation missing in model
    Miguel,
    #[allow(missing_docs)] // documentation missing in model
    Mizuki,
    #[allow(missing_docs)] // documentation missing in model
    Naja,
    #[allow(missing_docs)] // documentation missing in model
    Nicole,
    #[allow(missing_docs)] // documentation missing in model
    Penelope,
    #[allow(missing_docs)] // documentation missing in model
    Raveena,
    #[allow(missing_docs)] // documentation missing in model
    Ricardo,
    #[allow(missing_docs)] // documentation missing in model
    Ruben,
    #[allow(missing_docs)] // documentation missing in model
    Russell,
    #[allow(missing_docs)] // documentation missing in model
    Salli,
    #[allow(missing_docs)] // documentation missing in model
    Seoyeon,
    #[allow(missing_docs)] // documentation missing in model
    Takumi,
    #[allow(missing_docs)] // documentation missing in model
    Tatyana,
    #[allow(missing_docs)] // documentation missing in model
    Vicki,
    #[allow(missing_docs)] // documentation missing in model
    Vitoria,
    #[allow(missing_docs)] // documentation missing in model
    Zeina,
    #[allow(missing_docs)] // documentation missing in model
    Zhiyu,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for VoiceId {
    fn from(s: &str) -> Self {
        match s {
            "AMY" => VoiceId::Amy,
            "ASTRID" => VoiceId::Astrid,
            "BIANCA" => VoiceId::Bianca,
            "BRIAN" => VoiceId::Brian,
            "CAMILA" => VoiceId::Camila,
            "CARLA" => VoiceId::Carla,
            "CARMEN" => VoiceId::Carmen,
            "CELINE" => VoiceId::Celine,
            "CHANTAL" => VoiceId::Chantal,
            "CONCHITA" => VoiceId::Conchita,
            "CRISTIANO" => VoiceId::Cristiano,
            "DORA" => VoiceId::Dora,
            "EMMA" => VoiceId::Emma,
            "ENRIQUE" => VoiceId::Enrique,
            "EWA" => VoiceId::Ewa,
            "FILIZ" => VoiceId::Filiz,
            "GERAINT" => VoiceId::Geraint,
            "GIORGIO" => VoiceId::Giorgio,
            "GWYNETH" => VoiceId::Gwyneth,
            "HANS" => VoiceId::Hans,
            "INES" => VoiceId::Ines,
            "IVY" => VoiceId::Ivy,
            "JACEK" => VoiceId::Jacek,
            "JAN" => VoiceId::Jan,
            "JOANNA" => VoiceId::Joanna,
            "JOEY" => VoiceId::Joey,
            "JUSTIN" => VoiceId::Justin,
            "KARL" => VoiceId::Karl,
            "KENDRA" => VoiceId::Kendra,
            "KIMBERLY" => VoiceId::Kimberly,
            "LEA" => VoiceId::Lea,
            "LIV" => VoiceId::Liv,
            "LOTTE" => VoiceId::Lotte,
            "LUCIA" => VoiceId::Lucia,
            "LUPE" => VoiceId::Lupe,
            "MADS" => VoiceId::Mads,
            "MAJA" => VoiceId::Maja,
            "MARLENE" => VoiceId::Marlene,
            "MATHIEU" => VoiceId::Mathieu,
            "MATTHEW" => VoiceId::Matthew,
            "MAXIM" => VoiceId::Maxim,
            "MIA" => VoiceId::Mia,
            "MIGUEL" => VoiceId::Miguel,
            "MIZUKI" => VoiceId::Mizuki,
            "NAJA" => VoiceId::Naja,
            "NICOLE" => VoiceId::Nicole,
            "PENELOPE" => VoiceId::Penelope,
            "RAVEENA" => VoiceId::Raveena,
            "RICARDO" => VoiceId::Ricardo,
            "RUBEN" => VoiceId::Ruben,
            "RUSSELL" => VoiceId::Russell,
            "SALLI" => VoiceId::Salli,
            "SEOYEON" => VoiceId::Seoyeon,
            "TAKUMI" => VoiceId::Takumi,
            "TATYANA" => VoiceId::Tatyana,
            "VICKI" => VoiceId::Vicki,
            "VITORIA" => VoiceId::Vitoria,
            "ZEINA" => VoiceId::Zeina,
            "ZHIYU" => VoiceId::Zhiyu,
            other => VoiceId::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for VoiceId {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(VoiceId::from(s))
    }
}
impl VoiceId {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            VoiceId::Amy => "AMY",
            VoiceId::Astrid => "ASTRID",
            VoiceId::Bianca => "BIANCA",
            VoiceId::Brian => "BRIAN",
            VoiceId::Camila => "CAMILA",
            VoiceId::Carla => "CARLA",
            VoiceId::Carmen => "CARMEN",
            VoiceId::Celine => "CELINE",
            VoiceId::Chantal => "CHANTAL",
            VoiceId::Conchita => "CONCHITA",
            VoiceId::Cristiano => "CRISTIANO",
            VoiceId::Dora => "DORA",
            VoiceId::Emma => "EMMA",
            VoiceId::Enrique => "ENRIQUE",
            VoiceId::Ewa => "EWA",
            VoiceId::Filiz => "FILIZ",
            VoiceId::Geraint => "GERAINT",
            VoiceId::Giorgio => "GIORGIO",
            VoiceId::Gwyneth => "GWYNETH",
            VoiceId::Hans => "HANS",
            VoiceId::Ines => "INES",
            VoiceId::Ivy => "IVY",
            VoiceId::Jacek => "JACEK",
            VoiceId::Jan => "JAN",
            VoiceId::Joanna => "JOANNA",
            VoiceId::Joey => "JOEY",
            VoiceId::Justin => "JUSTIN",
            VoiceId::Karl => "KARL",
            VoiceId::Kendra => "KENDRA",
            VoiceId::Kimberly => "KIMBERLY",
            VoiceId::Lea => "LEA",
            VoiceId::Liv => "LIV",
            VoiceId::Lotte => "LOTTE",
            VoiceId::Lucia => "LUCIA",
            VoiceId::Lupe => "LUPE",
            VoiceId::Mads => "MADS",
            VoiceId::Maja => "MAJA",
            VoiceId::Marlene => "MARLENE",
            VoiceId::Mathieu => "MATHIEU",
            VoiceId::Matthew => "MATTHEW",
            VoiceId::Maxim => "MAXIM",
            VoiceId::Mia => "MIA",
            VoiceId::Miguel => "MIGUEL",
            VoiceId::Mizuki => "MIZUKI",
            VoiceId::Naja => "NAJA",
            VoiceId::Nicole => "NICOLE",
            VoiceId::Penelope => "PENELOPE",
            VoiceId::Raveena => "RAVEENA",
            VoiceId::Ricardo => "RICARDO",
            VoiceId::Ruben => "RUBEN",
            VoiceId::Russell => "RUSSELL",
            VoiceId::Salli => "SALLI",
            VoiceId::Seoyeon => "SEOYEON",
            VoiceId::Takumi => "TAKUMI",
            VoiceId::Tatyana => "TATYANA",
            VoiceId::Vicki => "VICKI",
            VoiceId::Vitoria => "VITORIA",
            VoiceId::Zeina => "ZEINA",
            VoiceId::Zhiyu => "ZHIYU",
            VoiceId::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AMY",
            "ASTRID",
            "BIANCA",
            "BRIAN",
            "CAMILA",
            "CARLA",
            "CARMEN",
            "CELINE",
            "CHANTAL",
            "CONCHITA",
            "CRISTIANO",
            "DORA",
            "EMMA",
            "ENRIQUE",
            "EWA",
            "FILIZ",
            "GERAINT",
            "GIORGIO",
            "GWYNETH",
            "HANS",
            "INES",
            "IVY",
            "JACEK",
            "JAN",
            "JOANNA",
            "JOEY",
            "JUSTIN",
            "KARL",
            "KENDRA",
            "KIMBERLY",
            "LEA",
            "LIV",
            "LOTTE",
            "LUCIA",
            "LUPE",
            "MADS",
            "MAJA",
            "MARLENE",
            "MATHIEU",
            "MATTHEW",
            "MAXIM",
            "MIA",
            "MIGUEL",
            "MIZUKI",
            "NAJA",
            "NICOLE",
            "PENELOPE",
            "RAVEENA",
            "RICARDO",
            "RUBEN",
            "RUSSELL",
            "SALLI",
            "SEOYEON",
            "TAKUMI",
            "TATYANA",
            "VICKI",
            "VITORIA",
            "ZEINA",
            "ZHIYU",
        ]
    }
}
impl ::std::convert::AsRef<str> for VoiceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl VoiceId {
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
impl ::std::fmt::Display for VoiceId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            VoiceId::Amy => write!(f, "AMY"),
            VoiceId::Astrid => write!(f, "ASTRID"),
            VoiceId::Bianca => write!(f, "BIANCA"),
            VoiceId::Brian => write!(f, "BRIAN"),
            VoiceId::Camila => write!(f, "CAMILA"),
            VoiceId::Carla => write!(f, "CARLA"),
            VoiceId::Carmen => write!(f, "CARMEN"),
            VoiceId::Celine => write!(f, "CELINE"),
            VoiceId::Chantal => write!(f, "CHANTAL"),
            VoiceId::Conchita => write!(f, "CONCHITA"),
            VoiceId::Cristiano => write!(f, "CRISTIANO"),
            VoiceId::Dora => write!(f, "DORA"),
            VoiceId::Emma => write!(f, "EMMA"),
            VoiceId::Enrique => write!(f, "ENRIQUE"),
            VoiceId::Ewa => write!(f, "EWA"),
            VoiceId::Filiz => write!(f, "FILIZ"),
            VoiceId::Geraint => write!(f, "GERAINT"),
            VoiceId::Giorgio => write!(f, "GIORGIO"),
            VoiceId::Gwyneth => write!(f, "GWYNETH"),
            VoiceId::Hans => write!(f, "HANS"),
            VoiceId::Ines => write!(f, "INES"),
            VoiceId::Ivy => write!(f, "IVY"),
            VoiceId::Jacek => write!(f, "JACEK"),
            VoiceId::Jan => write!(f, "JAN"),
            VoiceId::Joanna => write!(f, "JOANNA"),
            VoiceId::Joey => write!(f, "JOEY"),
            VoiceId::Justin => write!(f, "JUSTIN"),
            VoiceId::Karl => write!(f, "KARL"),
            VoiceId::Kendra => write!(f, "KENDRA"),
            VoiceId::Kimberly => write!(f, "KIMBERLY"),
            VoiceId::Lea => write!(f, "LEA"),
            VoiceId::Liv => write!(f, "LIV"),
            VoiceId::Lotte => write!(f, "LOTTE"),
            VoiceId::Lucia => write!(f, "LUCIA"),
            VoiceId::Lupe => write!(f, "LUPE"),
            VoiceId::Mads => write!(f, "MADS"),
            VoiceId::Maja => write!(f, "MAJA"),
            VoiceId::Marlene => write!(f, "MARLENE"),
            VoiceId::Mathieu => write!(f, "MATHIEU"),
            VoiceId::Matthew => write!(f, "MATTHEW"),
            VoiceId::Maxim => write!(f, "MAXIM"),
            VoiceId::Mia => write!(f, "MIA"),
            VoiceId::Miguel => write!(f, "MIGUEL"),
            VoiceId::Mizuki => write!(f, "MIZUKI"),
            VoiceId::Naja => write!(f, "NAJA"),
            VoiceId::Nicole => write!(f, "NICOLE"),
            VoiceId::Penelope => write!(f, "PENELOPE"),
            VoiceId::Raveena => write!(f, "RAVEENA"),
            VoiceId::Ricardo => write!(f, "RICARDO"),
            VoiceId::Ruben => write!(f, "RUBEN"),
            VoiceId::Russell => write!(f, "RUSSELL"),
            VoiceId::Salli => write!(f, "SALLI"),
            VoiceId::Seoyeon => write!(f, "SEOYEON"),
            VoiceId::Takumi => write!(f, "TAKUMI"),
            VoiceId::Tatyana => write!(f, "TATYANA"),
            VoiceId::Vicki => write!(f, "VICKI"),
            VoiceId::Vitoria => write!(f, "VITORIA"),
            VoiceId::Zeina => write!(f, "ZEINA"),
            VoiceId::Zhiyu => write!(f, "ZHIYU"),
            VoiceId::Unknown(value) => write!(f, "{}", value),
        }
    }
}
