// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A block of content that you pass to, or receive from, a Amazon Bedrock session in an invocation step. You pass the content to a session in the <code>payLoad</code> of the <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_PutInvocationStep.html">PutInvocationStep</a> API operation. You retrieve the content with the <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_GetInvocationStep.html">GetInvocationStep</a> API operation.</p>
/// <p>For more information about sessions, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/sessions.html">Store and retrieve conversation history and context with Amazon Bedrock sessions</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum BedrockSessionContentBlock {
    /// <p>The image in the invocation step.</p>
    Image(crate::types::ImageBlock),
    /// <p>The text in the invocation step.</p>
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
impl BedrockSessionContentBlock {
    /// Tries to convert the enum instance into [`Image`](crate::types::BedrockSessionContentBlock::Image), extracting the inner [`ImageBlock`](crate::types::ImageBlock).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_image(&self) -> ::std::result::Result<&crate::types::ImageBlock, &Self> {
        if let BedrockSessionContentBlock::Image(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Image`](crate::types::BedrockSessionContentBlock::Image).
    pub fn is_image(&self) -> bool {
        self.as_image().is_ok()
    }
    /// Tries to convert the enum instance into [`Text`](crate::types::BedrockSessionContentBlock::Text), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_text(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let BedrockSessionContentBlock::Text(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Text`](crate::types::BedrockSessionContentBlock::Text).
    pub fn is_text(&self) -> bool {
        self.as_text().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for BedrockSessionContentBlock {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::std::write!(f, "*** Sensitive Data Redacted ***")
    }
}
