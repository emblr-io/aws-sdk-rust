// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A system content block.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum SystemContentBlock {
    /// <p>CachePoint to include in the system prompt.</p>
    CachePoint(crate::types::CachePointBlock),
    /// <p>A content block to assess with the guardrail. Use with the <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html">Converse</a> or <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html">ConverseStream</a> API operations.</p>
    /// <p>For more information, see <i>Use a guardrail with the Converse API</i> in the <i>Amazon Bedrock User Guide</i>.</p>
    GuardContent(crate::types::GuardrailConverseContentBlock),
    /// <p>A system prompt for the model.</p>
    Text(::std::string::String),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl SystemContentBlock {
    /// Tries to convert the enum instance into [`CachePoint`](crate::types::SystemContentBlock::CachePoint), extracting the inner [`CachePointBlock`](crate::types::CachePointBlock).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cache_point(&self) -> ::std::result::Result<&crate::types::CachePointBlock, &Self> {
        if let SystemContentBlock::CachePoint(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CachePoint`](crate::types::SystemContentBlock::CachePoint).
    pub fn is_cache_point(&self) -> bool {
        self.as_cache_point().is_ok()
    }
    /// Tries to convert the enum instance into [`GuardContent`](crate::types::SystemContentBlock::GuardContent), extracting the inner [`GuardrailConverseContentBlock`](crate::types::GuardrailConverseContentBlock).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_guard_content(&self) -> ::std::result::Result<&crate::types::GuardrailConverseContentBlock, &Self> {
        if let SystemContentBlock::GuardContent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GuardContent`](crate::types::SystemContentBlock::GuardContent).
    pub fn is_guard_content(&self) -> bool {
        self.as_guard_content().is_ok()
    }
    /// Tries to convert the enum instance into [`Text`](crate::types::SystemContentBlock::Text), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_text(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let SystemContentBlock::Text(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Text`](crate::types::SystemContentBlock::Text).
    pub fn is_text(&self) -> bool {
        self.as_text().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
