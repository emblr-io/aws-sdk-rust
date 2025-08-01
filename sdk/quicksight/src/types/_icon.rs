// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Icon`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let icon = unimplemented!();
/// match icon {
///     Icon::ArrowDown => { /* ... */ },
///     Icon::ArrowDownLeft => { /* ... */ },
///     Icon::ArrowDownRight => { /* ... */ },
///     Icon::ArrowLeft => { /* ... */ },
///     Icon::ArrowRight => { /* ... */ },
///     Icon::ArrowUp => { /* ... */ },
///     Icon::ArrowUpLeft => { /* ... */ },
///     Icon::ArrowUpRight => { /* ... */ },
///     Icon::CaretDown => { /* ... */ },
///     Icon::CaretUp => { /* ... */ },
///     Icon::Checkmark => { /* ... */ },
///     Icon::Circle => { /* ... */ },
///     Icon::FaceDown => { /* ... */ },
///     Icon::FaceFlat => { /* ... */ },
///     Icon::FaceUp => { /* ... */ },
///     Icon::Flag => { /* ... */ },
///     Icon::Minus => { /* ... */ },
///     Icon::OneBar => { /* ... */ },
///     Icon::Plus => { /* ... */ },
///     Icon::Square => { /* ... */ },
///     Icon::ThreeBar => { /* ... */ },
///     Icon::ThumbsDown => { /* ... */ },
///     Icon::ThumbsUp => { /* ... */ },
///     Icon::Triangle => { /* ... */ },
///     Icon::TwoBar => { /* ... */ },
///     Icon::X => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `icon` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Icon::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Icon::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Icon::NewFeature` is defined.
/// Specifically, when `icon` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Icon::NewFeature` also yielding `"NewFeature"`.
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
pub enum Icon {
    #[allow(missing_docs)] // documentation missing in model
    ArrowDown,
    #[allow(missing_docs)] // documentation missing in model
    ArrowDownLeft,
    #[allow(missing_docs)] // documentation missing in model
    ArrowDownRight,
    #[allow(missing_docs)] // documentation missing in model
    ArrowLeft,
    #[allow(missing_docs)] // documentation missing in model
    ArrowRight,
    #[allow(missing_docs)] // documentation missing in model
    ArrowUp,
    #[allow(missing_docs)] // documentation missing in model
    ArrowUpLeft,
    #[allow(missing_docs)] // documentation missing in model
    ArrowUpRight,
    #[allow(missing_docs)] // documentation missing in model
    CaretDown,
    #[allow(missing_docs)] // documentation missing in model
    CaretUp,
    #[allow(missing_docs)] // documentation missing in model
    Checkmark,
    #[allow(missing_docs)] // documentation missing in model
    Circle,
    #[allow(missing_docs)] // documentation missing in model
    FaceDown,
    #[allow(missing_docs)] // documentation missing in model
    FaceFlat,
    #[allow(missing_docs)] // documentation missing in model
    FaceUp,
    #[allow(missing_docs)] // documentation missing in model
    Flag,
    #[allow(missing_docs)] // documentation missing in model
    Minus,
    #[allow(missing_docs)] // documentation missing in model
    OneBar,
    #[allow(missing_docs)] // documentation missing in model
    Plus,
    #[allow(missing_docs)] // documentation missing in model
    Square,
    #[allow(missing_docs)] // documentation missing in model
    ThreeBar,
    #[allow(missing_docs)] // documentation missing in model
    ThumbsDown,
    #[allow(missing_docs)] // documentation missing in model
    ThumbsUp,
    #[allow(missing_docs)] // documentation missing in model
    Triangle,
    #[allow(missing_docs)] // documentation missing in model
    TwoBar,
    #[allow(missing_docs)] // documentation missing in model
    X,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Icon {
    fn from(s: &str) -> Self {
        match s {
            "ARROW_DOWN" => Icon::ArrowDown,
            "ARROW_DOWN_LEFT" => Icon::ArrowDownLeft,
            "ARROW_DOWN_RIGHT" => Icon::ArrowDownRight,
            "ARROW_LEFT" => Icon::ArrowLeft,
            "ARROW_RIGHT" => Icon::ArrowRight,
            "ARROW_UP" => Icon::ArrowUp,
            "ARROW_UP_LEFT" => Icon::ArrowUpLeft,
            "ARROW_UP_RIGHT" => Icon::ArrowUpRight,
            "CARET_DOWN" => Icon::CaretDown,
            "CARET_UP" => Icon::CaretUp,
            "CHECKMARK" => Icon::Checkmark,
            "CIRCLE" => Icon::Circle,
            "FACE_DOWN" => Icon::FaceDown,
            "FACE_FLAT" => Icon::FaceFlat,
            "FACE_UP" => Icon::FaceUp,
            "FLAG" => Icon::Flag,
            "MINUS" => Icon::Minus,
            "ONE_BAR" => Icon::OneBar,
            "PLUS" => Icon::Plus,
            "SQUARE" => Icon::Square,
            "THREE_BAR" => Icon::ThreeBar,
            "THUMBS_DOWN" => Icon::ThumbsDown,
            "THUMBS_UP" => Icon::ThumbsUp,
            "TRIANGLE" => Icon::Triangle,
            "TWO_BAR" => Icon::TwoBar,
            "X" => Icon::X,
            other => Icon::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Icon {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Icon::from(s))
    }
}
impl Icon {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Icon::ArrowDown => "ARROW_DOWN",
            Icon::ArrowDownLeft => "ARROW_DOWN_LEFT",
            Icon::ArrowDownRight => "ARROW_DOWN_RIGHT",
            Icon::ArrowLeft => "ARROW_LEFT",
            Icon::ArrowRight => "ARROW_RIGHT",
            Icon::ArrowUp => "ARROW_UP",
            Icon::ArrowUpLeft => "ARROW_UP_LEFT",
            Icon::ArrowUpRight => "ARROW_UP_RIGHT",
            Icon::CaretDown => "CARET_DOWN",
            Icon::CaretUp => "CARET_UP",
            Icon::Checkmark => "CHECKMARK",
            Icon::Circle => "CIRCLE",
            Icon::FaceDown => "FACE_DOWN",
            Icon::FaceFlat => "FACE_FLAT",
            Icon::FaceUp => "FACE_UP",
            Icon::Flag => "FLAG",
            Icon::Minus => "MINUS",
            Icon::OneBar => "ONE_BAR",
            Icon::Plus => "PLUS",
            Icon::Square => "SQUARE",
            Icon::ThreeBar => "THREE_BAR",
            Icon::ThumbsDown => "THUMBS_DOWN",
            Icon::ThumbsUp => "THUMBS_UP",
            Icon::Triangle => "TRIANGLE",
            Icon::TwoBar => "TWO_BAR",
            Icon::X => "X",
            Icon::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ARROW_DOWN",
            "ARROW_DOWN_LEFT",
            "ARROW_DOWN_RIGHT",
            "ARROW_LEFT",
            "ARROW_RIGHT",
            "ARROW_UP",
            "ARROW_UP_LEFT",
            "ARROW_UP_RIGHT",
            "CARET_DOWN",
            "CARET_UP",
            "CHECKMARK",
            "CIRCLE",
            "FACE_DOWN",
            "FACE_FLAT",
            "FACE_UP",
            "FLAG",
            "MINUS",
            "ONE_BAR",
            "PLUS",
            "SQUARE",
            "THREE_BAR",
            "THUMBS_DOWN",
            "THUMBS_UP",
            "TRIANGLE",
            "TWO_BAR",
            "X",
        ]
    }
}
impl ::std::convert::AsRef<str> for Icon {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Icon {
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
impl ::std::fmt::Display for Icon {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Icon::ArrowDown => write!(f, "ARROW_DOWN"),
            Icon::ArrowDownLeft => write!(f, "ARROW_DOWN_LEFT"),
            Icon::ArrowDownRight => write!(f, "ARROW_DOWN_RIGHT"),
            Icon::ArrowLeft => write!(f, "ARROW_LEFT"),
            Icon::ArrowRight => write!(f, "ARROW_RIGHT"),
            Icon::ArrowUp => write!(f, "ARROW_UP"),
            Icon::ArrowUpLeft => write!(f, "ARROW_UP_LEFT"),
            Icon::ArrowUpRight => write!(f, "ARROW_UP_RIGHT"),
            Icon::CaretDown => write!(f, "CARET_DOWN"),
            Icon::CaretUp => write!(f, "CARET_UP"),
            Icon::Checkmark => write!(f, "CHECKMARK"),
            Icon::Circle => write!(f, "CIRCLE"),
            Icon::FaceDown => write!(f, "FACE_DOWN"),
            Icon::FaceFlat => write!(f, "FACE_FLAT"),
            Icon::FaceUp => write!(f, "FACE_UP"),
            Icon::Flag => write!(f, "FLAG"),
            Icon::Minus => write!(f, "MINUS"),
            Icon::OneBar => write!(f, "ONE_BAR"),
            Icon::Plus => write!(f, "PLUS"),
            Icon::Square => write!(f, "SQUARE"),
            Icon::ThreeBar => write!(f, "THREE_BAR"),
            Icon::ThumbsDown => write!(f, "THUMBS_DOWN"),
            Icon::ThumbsUp => write!(f, "THUMBS_UP"),
            Icon::Triangle => write!(f, "TRIANGLE"),
            Icon::TwoBar => write!(f, "TWO_BAR"),
            Icon::X => write!(f, "X"),
            Icon::Unknown(value) => write!(f, "{}", value),
        }
    }
}
