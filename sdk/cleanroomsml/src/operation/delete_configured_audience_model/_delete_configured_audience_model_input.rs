// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConfiguredAudienceModelInput {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model that you want to delete.</p>
    pub configured_audience_model_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteConfiguredAudienceModelInput {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model that you want to delete.</p>
    pub fn configured_audience_model_arn(&self) -> ::std::option::Option<&str> {
        self.configured_audience_model_arn.as_deref()
    }
}
impl DeleteConfiguredAudienceModelInput {
    /// Creates a new builder-style object to manufacture [`DeleteConfiguredAudienceModelInput`](crate::operation::delete_configured_audience_model::DeleteConfiguredAudienceModelInput).
    pub fn builder() -> crate::operation::delete_configured_audience_model::builders::DeleteConfiguredAudienceModelInputBuilder {
        crate::operation::delete_configured_audience_model::builders::DeleteConfiguredAudienceModelInputBuilder::default()
    }
}

/// A builder for [`DeleteConfiguredAudienceModelInput`](crate::operation::delete_configured_audience_model::DeleteConfiguredAudienceModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConfiguredAudienceModelInputBuilder {
    pub(crate) configured_audience_model_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteConfiguredAudienceModelInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the configured audience model that you want to delete.</p>
    /// This field is required.
    pub fn configured_audience_model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configured_audience_model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured audience model that you want to delete.</p>
    pub fn set_configured_audience_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configured_audience_model_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configured audience model that you want to delete.</p>
    pub fn get_configured_audience_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configured_audience_model_arn
    }
    /// Consumes the builder and constructs a [`DeleteConfiguredAudienceModelInput`](crate::operation::delete_configured_audience_model::DeleteConfiguredAudienceModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_configured_audience_model::DeleteConfiguredAudienceModelInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_configured_audience_model::DeleteConfiguredAudienceModelInput {
            configured_audience_model_arn: self.configured_audience_model_arn,
        })
    }
}
