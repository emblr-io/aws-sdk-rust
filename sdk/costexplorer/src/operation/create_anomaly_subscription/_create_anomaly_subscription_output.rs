// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAnomalySubscriptionOutput {
    /// <p>The unique identifier of your newly created cost anomaly subscription.</p>
    pub subscription_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateAnomalySubscriptionOutput {
    /// <p>The unique identifier of your newly created cost anomaly subscription.</p>
    pub fn subscription_arn(&self) -> &str {
        use std::ops::Deref;
        self.subscription_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAnomalySubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAnomalySubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`CreateAnomalySubscriptionOutput`](crate::operation::create_anomaly_subscription::CreateAnomalySubscriptionOutput).
    pub fn builder() -> crate::operation::create_anomaly_subscription::builders::CreateAnomalySubscriptionOutputBuilder {
        crate::operation::create_anomaly_subscription::builders::CreateAnomalySubscriptionOutputBuilder::default()
    }
}

/// A builder for [`CreateAnomalySubscriptionOutput`](crate::operation::create_anomaly_subscription::CreateAnomalySubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAnomalySubscriptionOutputBuilder {
    pub(crate) subscription_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAnomalySubscriptionOutputBuilder {
    /// <p>The unique identifier of your newly created cost anomaly subscription.</p>
    /// This field is required.
    pub fn subscription_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of your newly created cost anomaly subscription.</p>
    pub fn set_subscription_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_arn = input;
        self
    }
    /// <p>The unique identifier of your newly created cost anomaly subscription.</p>
    pub fn get_subscription_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAnomalySubscriptionOutput`](crate::operation::create_anomaly_subscription::CreateAnomalySubscriptionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`subscription_arn`](crate::operation::create_anomaly_subscription::builders::CreateAnomalySubscriptionOutputBuilder::subscription_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_anomaly_subscription::CreateAnomalySubscriptionOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_anomaly_subscription::CreateAnomalySubscriptionOutput {
            subscription_arn: self.subscription_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subscription_arn",
                    "subscription_arn was not specified but it is required when building CreateAnomalySubscriptionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
