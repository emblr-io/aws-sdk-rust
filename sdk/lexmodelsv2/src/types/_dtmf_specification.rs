// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the DTMF input specifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DtmfSpecification {
    /// <p>The maximum number of DTMF digits allowed in an utterance.</p>
    pub max_length: i32,
    /// <p>How long the bot should wait after the last DTMF character input before assuming that the input has concluded.</p>
    pub end_timeout_ms: i32,
    /// <p>The DTMF character that clears the accumulated DTMF digits and immediately ends the input.</p>
    pub deletion_character: ::std::string::String,
    /// <p>The DTMF character that immediately ends input. If the user does not press this character, the input ends after the end timeout.</p>
    pub end_character: ::std::string::String,
}
impl DtmfSpecification {
    /// <p>The maximum number of DTMF digits allowed in an utterance.</p>
    pub fn max_length(&self) -> i32 {
        self.max_length
    }
    /// <p>How long the bot should wait after the last DTMF character input before assuming that the input has concluded.</p>
    pub fn end_timeout_ms(&self) -> i32 {
        self.end_timeout_ms
    }
    /// <p>The DTMF character that clears the accumulated DTMF digits and immediately ends the input.</p>
    pub fn deletion_character(&self) -> &str {
        use std::ops::Deref;
        self.deletion_character.deref()
    }
    /// <p>The DTMF character that immediately ends input. If the user does not press this character, the input ends after the end timeout.</p>
    pub fn end_character(&self) -> &str {
        use std::ops::Deref;
        self.end_character.deref()
    }
}
impl DtmfSpecification {
    /// Creates a new builder-style object to manufacture [`DtmfSpecification`](crate::types::DtmfSpecification).
    pub fn builder() -> crate::types::builders::DtmfSpecificationBuilder {
        crate::types::builders::DtmfSpecificationBuilder::default()
    }
}

/// A builder for [`DtmfSpecification`](crate::types::DtmfSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DtmfSpecificationBuilder {
    pub(crate) max_length: ::std::option::Option<i32>,
    pub(crate) end_timeout_ms: ::std::option::Option<i32>,
    pub(crate) deletion_character: ::std::option::Option<::std::string::String>,
    pub(crate) end_character: ::std::option::Option<::std::string::String>,
}
impl DtmfSpecificationBuilder {
    /// <p>The maximum number of DTMF digits allowed in an utterance.</p>
    /// This field is required.
    pub fn max_length(mut self, input: i32) -> Self {
        self.max_length = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of DTMF digits allowed in an utterance.</p>
    pub fn set_max_length(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_length = input;
        self
    }
    /// <p>The maximum number of DTMF digits allowed in an utterance.</p>
    pub fn get_max_length(&self) -> &::std::option::Option<i32> {
        &self.max_length
    }
    /// <p>How long the bot should wait after the last DTMF character input before assuming that the input has concluded.</p>
    /// This field is required.
    pub fn end_timeout_ms(mut self, input: i32) -> Self {
        self.end_timeout_ms = ::std::option::Option::Some(input);
        self
    }
    /// <p>How long the bot should wait after the last DTMF character input before assuming that the input has concluded.</p>
    pub fn set_end_timeout_ms(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_timeout_ms = input;
        self
    }
    /// <p>How long the bot should wait after the last DTMF character input before assuming that the input has concluded.</p>
    pub fn get_end_timeout_ms(&self) -> &::std::option::Option<i32> {
        &self.end_timeout_ms
    }
    /// <p>The DTMF character that clears the accumulated DTMF digits and immediately ends the input.</p>
    /// This field is required.
    pub fn deletion_character(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deletion_character = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DTMF character that clears the accumulated DTMF digits and immediately ends the input.</p>
    pub fn set_deletion_character(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deletion_character = input;
        self
    }
    /// <p>The DTMF character that clears the accumulated DTMF digits and immediately ends the input.</p>
    pub fn get_deletion_character(&self) -> &::std::option::Option<::std::string::String> {
        &self.deletion_character
    }
    /// <p>The DTMF character that immediately ends input. If the user does not press this character, the input ends after the end timeout.</p>
    /// This field is required.
    pub fn end_character(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_character = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DTMF character that immediately ends input. If the user does not press this character, the input ends after the end timeout.</p>
    pub fn set_end_character(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_character = input;
        self
    }
    /// <p>The DTMF character that immediately ends input. If the user does not press this character, the input ends after the end timeout.</p>
    pub fn get_end_character(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_character
    }
    /// Consumes the builder and constructs a [`DtmfSpecification`](crate::types::DtmfSpecification).
    /// This method will fail if any of the following fields are not set:
    /// - [`max_length`](crate::types::builders::DtmfSpecificationBuilder::max_length)
    /// - [`end_timeout_ms`](crate::types::builders::DtmfSpecificationBuilder::end_timeout_ms)
    /// - [`deletion_character`](crate::types::builders::DtmfSpecificationBuilder::deletion_character)
    /// - [`end_character`](crate::types::builders::DtmfSpecificationBuilder::end_character)
    pub fn build(self) -> ::std::result::Result<crate::types::DtmfSpecification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DtmfSpecification {
            max_length: self.max_length.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_length",
                    "max_length was not specified but it is required when building DtmfSpecification",
                )
            })?,
            end_timeout_ms: self.end_timeout_ms.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_timeout_ms",
                    "end_timeout_ms was not specified but it is required when building DtmfSpecification",
                )
            })?,
            deletion_character: self.deletion_character.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "deletion_character",
                    "deletion_character was not specified but it is required when building DtmfSpecification",
                )
            })?,
            end_character: self.end_character.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_character",
                    "end_character was not specified but it is required when building DtmfSpecification",
                )
            })?,
        })
    }
}
