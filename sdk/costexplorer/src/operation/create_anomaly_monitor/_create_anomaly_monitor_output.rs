// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAnomalyMonitorOutput {
    /// <p>The unique identifier of your newly created cost anomaly detection monitor.</p>
    pub monitor_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateAnomalyMonitorOutput {
    /// <p>The unique identifier of your newly created cost anomaly detection monitor.</p>
    pub fn monitor_arn(&self) -> &str {
        use std::ops::Deref;
        self.monitor_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAnomalyMonitorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAnomalyMonitorOutput {
    /// Creates a new builder-style object to manufacture [`CreateAnomalyMonitorOutput`](crate::operation::create_anomaly_monitor::CreateAnomalyMonitorOutput).
    pub fn builder() -> crate::operation::create_anomaly_monitor::builders::CreateAnomalyMonitorOutputBuilder {
        crate::operation::create_anomaly_monitor::builders::CreateAnomalyMonitorOutputBuilder::default()
    }
}

/// A builder for [`CreateAnomalyMonitorOutput`](crate::operation::create_anomaly_monitor::CreateAnomalyMonitorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAnomalyMonitorOutputBuilder {
    pub(crate) monitor_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAnomalyMonitorOutputBuilder {
    /// <p>The unique identifier of your newly created cost anomaly detection monitor.</p>
    /// This field is required.
    pub fn monitor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of your newly created cost anomaly detection monitor.</p>
    pub fn set_monitor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitor_arn = input;
        self
    }
    /// <p>The unique identifier of your newly created cost anomaly detection monitor.</p>
    pub fn get_monitor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitor_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAnomalyMonitorOutput`](crate::operation::create_anomaly_monitor::CreateAnomalyMonitorOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`monitor_arn`](crate::operation::create_anomaly_monitor::builders::CreateAnomalyMonitorOutputBuilder::monitor_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_anomaly_monitor::CreateAnomalyMonitorOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_anomaly_monitor::CreateAnomalyMonitorOutput {
            monitor_arn: self.monitor_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "monitor_arn",
                    "monitor_arn was not specified but it is required when building CreateAnomalyMonitorOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
