// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartEngagementOutput {
    /// <p>The ARN of the engagement.</p>
    pub engagement_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl StartEngagementOutput {
    /// <p>The ARN of the engagement.</p>
    pub fn engagement_arn(&self) -> &str {
        use std::ops::Deref;
        self.engagement_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for StartEngagementOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartEngagementOutput {
    /// Creates a new builder-style object to manufacture [`StartEngagementOutput`](crate::operation::start_engagement::StartEngagementOutput).
    pub fn builder() -> crate::operation::start_engagement::builders::StartEngagementOutputBuilder {
        crate::operation::start_engagement::builders::StartEngagementOutputBuilder::default()
    }
}

/// A builder for [`StartEngagementOutput`](crate::operation::start_engagement::StartEngagementOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartEngagementOutputBuilder {
    pub(crate) engagement_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartEngagementOutputBuilder {
    /// <p>The ARN of the engagement.</p>
    /// This field is required.
    pub fn engagement_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engagement_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the engagement.</p>
    pub fn set_engagement_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engagement_arn = input;
        self
    }
    /// <p>The ARN of the engagement.</p>
    pub fn get_engagement_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.engagement_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartEngagementOutput`](crate::operation::start_engagement::StartEngagementOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`engagement_arn`](crate::operation::start_engagement::builders::StartEngagementOutputBuilder::engagement_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_engagement::StartEngagementOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_engagement::StartEngagementOutput {
            engagement_arn: self.engagement_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "engagement_arn",
                    "engagement_arn was not specified but it is required when building StartEngagementOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
