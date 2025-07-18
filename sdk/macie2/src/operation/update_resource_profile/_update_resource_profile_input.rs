// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateResourceProfileInput {
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The new sensitivity score for the bucket. Valid values are: 100, assign the maximum score and apply the <i>Sensitive</i> label to the bucket; and, null (empty), assign a score that Amazon Macie calculates automatically after you submit the request.</p>
    pub sensitivity_score_override: ::std::option::Option<i32>,
}
impl UpdateResourceProfileInput {
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that the request applies to.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The new sensitivity score for the bucket. Valid values are: 100, assign the maximum score and apply the <i>Sensitive</i> label to the bucket; and, null (empty), assign a score that Amazon Macie calculates automatically after you submit the request.</p>
    pub fn sensitivity_score_override(&self) -> ::std::option::Option<i32> {
        self.sensitivity_score_override
    }
}
impl UpdateResourceProfileInput {
    /// Creates a new builder-style object to manufacture [`UpdateResourceProfileInput`](crate::operation::update_resource_profile::UpdateResourceProfileInput).
    pub fn builder() -> crate::operation::update_resource_profile::builders::UpdateResourceProfileInputBuilder {
        crate::operation::update_resource_profile::builders::UpdateResourceProfileInputBuilder::default()
    }
}

/// A builder for [`UpdateResourceProfileInput`](crate::operation::update_resource_profile::UpdateResourceProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateResourceProfileInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sensitivity_score_override: ::std::option::Option<i32>,
}
impl UpdateResourceProfileInputBuilder {
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
    /// <p>The new sensitivity score for the bucket. Valid values are: 100, assign the maximum score and apply the <i>Sensitive</i> label to the bucket; and, null (empty), assign a score that Amazon Macie calculates automatically after you submit the request.</p>
    pub fn sensitivity_score_override(mut self, input: i32) -> Self {
        self.sensitivity_score_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new sensitivity score for the bucket. Valid values are: 100, assign the maximum score and apply the <i>Sensitive</i> label to the bucket; and, null (empty), assign a score that Amazon Macie calculates automatically after you submit the request.</p>
    pub fn set_sensitivity_score_override(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sensitivity_score_override = input;
        self
    }
    /// <p>The new sensitivity score for the bucket. Valid values are: 100, assign the maximum score and apply the <i>Sensitive</i> label to the bucket; and, null (empty), assign a score that Amazon Macie calculates automatically after you submit the request.</p>
    pub fn get_sensitivity_score_override(&self) -> &::std::option::Option<i32> {
        &self.sensitivity_score_override
    }
    /// Consumes the builder and constructs a [`UpdateResourceProfileInput`](crate::operation::update_resource_profile::UpdateResourceProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_resource_profile::UpdateResourceProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_resource_profile::UpdateResourceProfileInput {
            resource_arn: self.resource_arn,
            sensitivity_score_override: self.sensitivity_score_override,
        })
    }
}
