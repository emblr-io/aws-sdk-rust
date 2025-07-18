// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetChallengeMetadataInput {
    /// <p>The Amazon Resource Name (ARN) of the challenge.</p>
    pub challenge_arn: ::std::option::Option<::std::string::String>,
}
impl GetChallengeMetadataInput {
    /// <p>The Amazon Resource Name (ARN) of the challenge.</p>
    pub fn challenge_arn(&self) -> ::std::option::Option<&str> {
        self.challenge_arn.as_deref()
    }
}
impl GetChallengeMetadataInput {
    /// Creates a new builder-style object to manufacture [`GetChallengeMetadataInput`](crate::operation::get_challenge_metadata::GetChallengeMetadataInput).
    pub fn builder() -> crate::operation::get_challenge_metadata::builders::GetChallengeMetadataInputBuilder {
        crate::operation::get_challenge_metadata::builders::GetChallengeMetadataInputBuilder::default()
    }
}

/// A builder for [`GetChallengeMetadataInput`](crate::operation::get_challenge_metadata::GetChallengeMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetChallengeMetadataInputBuilder {
    pub(crate) challenge_arn: ::std::option::Option<::std::string::String>,
}
impl GetChallengeMetadataInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the challenge.</p>
    /// This field is required.
    pub fn challenge_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.challenge_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the challenge.</p>
    pub fn set_challenge_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.challenge_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the challenge.</p>
    pub fn get_challenge_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.challenge_arn
    }
    /// Consumes the builder and constructs a [`GetChallengeMetadataInput`](crate::operation::get_challenge_metadata::GetChallengeMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_challenge_metadata::GetChallengeMetadataInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_challenge_metadata::GetChallengeMetadataInput {
            challenge_arn: self.challenge_arn,
        })
    }
}
