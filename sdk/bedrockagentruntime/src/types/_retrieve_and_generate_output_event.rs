// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A retrieve and generate output event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RetrieveAndGenerateOutputEvent {
    /// <p>A text response.</p>
    pub text: ::std::string::String,
}
impl RetrieveAndGenerateOutputEvent {
    /// <p>A text response.</p>
    pub fn text(&self) -> &str {
        use std::ops::Deref;
        self.text.deref()
    }
}
impl ::std::fmt::Debug for RetrieveAndGenerateOutputEvent {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RetrieveAndGenerateOutputEvent");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl RetrieveAndGenerateOutputEvent {
    /// Creates a new builder-style object to manufacture [`RetrieveAndGenerateOutputEvent`](crate::types::RetrieveAndGenerateOutputEvent).
    pub fn builder() -> crate::types::builders::RetrieveAndGenerateOutputEventBuilder {
        crate::types::builders::RetrieveAndGenerateOutputEventBuilder::default()
    }
}

/// A builder for [`RetrieveAndGenerateOutputEvent`](crate::types::RetrieveAndGenerateOutputEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RetrieveAndGenerateOutputEventBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
}
impl RetrieveAndGenerateOutputEventBuilder {
    /// <p>A text response.</p>
    /// This field is required.
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A text response.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>A text response.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// Consumes the builder and constructs a [`RetrieveAndGenerateOutputEvent`](crate::types::RetrieveAndGenerateOutputEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`text`](crate::types::builders::RetrieveAndGenerateOutputEventBuilder::text)
    pub fn build(self) -> ::std::result::Result<crate::types::RetrieveAndGenerateOutputEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RetrieveAndGenerateOutputEvent {
            text: self.text.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "text",
                    "text was not specified but it is required when building RetrieveAndGenerateOutputEvent",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for RetrieveAndGenerateOutputEventBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RetrieveAndGenerateOutputEventBuilder");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
