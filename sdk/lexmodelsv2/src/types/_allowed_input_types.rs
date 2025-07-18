// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the allowed input types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AllowedInputTypes {
    /// <p>Indicates whether audio input is allowed.</p>
    pub allow_audio_input: bool,
    /// <p>Indicates whether DTMF input is allowed.</p>
    pub allow_dtmf_input: bool,
}
impl AllowedInputTypes {
    /// <p>Indicates whether audio input is allowed.</p>
    pub fn allow_audio_input(&self) -> bool {
        self.allow_audio_input
    }
    /// <p>Indicates whether DTMF input is allowed.</p>
    pub fn allow_dtmf_input(&self) -> bool {
        self.allow_dtmf_input
    }
}
impl AllowedInputTypes {
    /// Creates a new builder-style object to manufacture [`AllowedInputTypes`](crate::types::AllowedInputTypes).
    pub fn builder() -> crate::types::builders::AllowedInputTypesBuilder {
        crate::types::builders::AllowedInputTypesBuilder::default()
    }
}

/// A builder for [`AllowedInputTypes`](crate::types::AllowedInputTypes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AllowedInputTypesBuilder {
    pub(crate) allow_audio_input: ::std::option::Option<bool>,
    pub(crate) allow_dtmf_input: ::std::option::Option<bool>,
}
impl AllowedInputTypesBuilder {
    /// <p>Indicates whether audio input is allowed.</p>
    /// This field is required.
    pub fn allow_audio_input(mut self, input: bool) -> Self {
        self.allow_audio_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether audio input is allowed.</p>
    pub fn set_allow_audio_input(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_audio_input = input;
        self
    }
    /// <p>Indicates whether audio input is allowed.</p>
    pub fn get_allow_audio_input(&self) -> &::std::option::Option<bool> {
        &self.allow_audio_input
    }
    /// <p>Indicates whether DTMF input is allowed.</p>
    /// This field is required.
    pub fn allow_dtmf_input(mut self, input: bool) -> Self {
        self.allow_dtmf_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether DTMF input is allowed.</p>
    pub fn set_allow_dtmf_input(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_dtmf_input = input;
        self
    }
    /// <p>Indicates whether DTMF input is allowed.</p>
    pub fn get_allow_dtmf_input(&self) -> &::std::option::Option<bool> {
        &self.allow_dtmf_input
    }
    /// Consumes the builder and constructs a [`AllowedInputTypes`](crate::types::AllowedInputTypes).
    /// This method will fail if any of the following fields are not set:
    /// - [`allow_audio_input`](crate::types::builders::AllowedInputTypesBuilder::allow_audio_input)
    /// - [`allow_dtmf_input`](crate::types::builders::AllowedInputTypesBuilder::allow_dtmf_input)
    pub fn build(self) -> ::std::result::Result<crate::types::AllowedInputTypes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AllowedInputTypes {
            allow_audio_input: self.allow_audio_input.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allow_audio_input",
                    "allow_audio_input was not specified but it is required when building AllowedInputTypes",
                )
            })?,
            allow_dtmf_input: self.allow_dtmf_input.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allow_dtmf_input",
                    "allow_dtmf_input was not specified but it is required when building AllowedInputTypes",
                )
            })?,
        })
    }
}
