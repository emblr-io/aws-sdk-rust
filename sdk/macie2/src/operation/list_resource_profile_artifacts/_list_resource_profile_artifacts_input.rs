// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceProfileArtifactsInput {
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl ListResourceProfileArtifactsInput {
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl ListResourceProfileArtifactsInput {
    /// Creates a new builder-style object to manufacture [`ListResourceProfileArtifactsInput`](crate::operation::list_resource_profile_artifacts::ListResourceProfileArtifactsInput).
    pub fn builder() -> crate::operation::list_resource_profile_artifacts::builders::ListResourceProfileArtifactsInputBuilder {
        crate::operation::list_resource_profile_artifacts::builders::ListResourceProfileArtifactsInputBuilder::default()
    }
}

/// A builder for [`ListResourceProfileArtifactsInput`](crate::operation::list_resource_profile_artifacts::ListResourceProfileArtifactsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceProfileArtifactsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl ListResourceProfileArtifactsInputBuilder {
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`ListResourceProfileArtifactsInput`](crate::operation::list_resource_profile_artifacts::ListResourceProfileArtifactsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resource_profile_artifacts::ListResourceProfileArtifactsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_resource_profile_artifacts::ListResourceProfileArtifactsInput {
            next_token: self.next_token,
            resource_arn: self.resource_arn,
        })
    }
}
