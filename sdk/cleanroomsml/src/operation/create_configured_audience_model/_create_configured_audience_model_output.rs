// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConfiguredAudienceModelOutput {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model.</p>
    pub configured_audience_model_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateConfiguredAudienceModelOutput {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model.</p>
    pub fn configured_audience_model_arn(&self) -> &str {
        use std::ops::Deref;
        self.configured_audience_model_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateConfiguredAudienceModelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateConfiguredAudienceModelOutput {
    /// Creates a new builder-style object to manufacture [`CreateConfiguredAudienceModelOutput`](crate::operation::create_configured_audience_model::CreateConfiguredAudienceModelOutput).
    pub fn builder() -> crate::operation::create_configured_audience_model::builders::CreateConfiguredAudienceModelOutputBuilder {
        crate::operation::create_configured_audience_model::builders::CreateConfiguredAudienceModelOutputBuilder::default()
    }
}

/// A builder for [`CreateConfiguredAudienceModelOutput`](crate::operation::create_configured_audience_model::CreateConfiguredAudienceModelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConfiguredAudienceModelOutputBuilder {
    pub(crate) configured_audience_model_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateConfiguredAudienceModelOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model.</p>
    /// This field is required.
    pub fn configured_audience_model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_audience_model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured audience model.</p>
    pub fn set_configured_audience_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_audience_model_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured audience model.</p>
    pub fn get_configured_audience_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_audience_model_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateConfiguredAudienceModelOutput`](crate::operation::create_configured_audience_model::CreateConfiguredAudienceModelOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`configured_audience_model_arn`](crate::operation::create_configured_audience_model::builders::CreateConfiguredAudienceModelOutputBuilder::configured_audience_model_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_configured_audience_model::CreateConfiguredAudienceModelOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_configured_audience_model::CreateConfiguredAudienceModelOutput {
            configured_audience_model_arn: self.configured_audience_model_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "configured_audience_model_arn",
                    "configured_audience_model_arn was not specified but it is required when building CreateConfiguredAudienceModelOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
