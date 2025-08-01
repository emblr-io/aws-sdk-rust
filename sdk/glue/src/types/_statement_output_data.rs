// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The code execution output in JSON format.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StatementOutputData {
    /// <p>The code execution output in text format.</p>
    pub text_plain: ::std::option::Option<::std::string::String>,
}
impl StatementOutputData {
    /// <p>The code execution output in text format.</p>
    pub fn text_plain(&self) -> ::std::option::Option<&str> {
        self.text_plain.as_deref()
    }
}
impl StatementOutputData {
    /// Creates a new builder-style object to manufacture [`StatementOutputData`](crate::types::StatementOutputData).
    pub fn builder() -> crate::types::builders::StatementOutputDataBuilder {
        crate::types::builders::StatementOutputDataBuilder::default()
    }
}

/// A builder for [`StatementOutputData`](crate::types::StatementOutputData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StatementOutputDataBuilder {
    pub(crate) text_plain: ::std::option::Option<::std::string::String>,
}
impl StatementOutputDataBuilder {
    /// <p>The code execution output in text format.</p>
    pub fn text_plain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text_plain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The code execution output in text format.</p>
    pub fn set_text_plain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text_plain = input;
        self
    }
    /// <p>The code execution output in text format.</p>
    pub fn get_text_plain(&self) -> &::std::option::Option<::std::string::String> {
        &self.text_plain
    }
    /// Consumes the builder and constructs a [`StatementOutputData`](crate::types::StatementOutputData).
    pub fn build(self) -> crate::types::StatementOutputData {
        crate::types::StatementOutputData { text_plain: self.text_plain }
    }
}
