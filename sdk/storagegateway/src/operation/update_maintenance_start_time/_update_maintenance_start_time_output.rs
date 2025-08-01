// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON object containing the Amazon Resource Name (ARN) of the gateway whose maintenance start time is updated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMaintenanceStartTimeOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateMaintenanceStartTimeOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateMaintenanceStartTimeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateMaintenanceStartTimeOutput {
    /// Creates a new builder-style object to manufacture [`UpdateMaintenanceStartTimeOutput`](crate::operation::update_maintenance_start_time::UpdateMaintenanceStartTimeOutput).
    pub fn builder() -> crate::operation::update_maintenance_start_time::builders::UpdateMaintenanceStartTimeOutputBuilder {
        crate::operation::update_maintenance_start_time::builders::UpdateMaintenanceStartTimeOutputBuilder::default()
    }
}

/// A builder for [`UpdateMaintenanceStartTimeOutput`](crate::operation::update_maintenance_start_time::UpdateMaintenanceStartTimeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMaintenanceStartTimeOutputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateMaintenanceStartTimeOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateMaintenanceStartTimeOutput`](crate::operation::update_maintenance_start_time::UpdateMaintenanceStartTimeOutput).
    pub fn build(self) -> crate::operation::update_maintenance_start_time::UpdateMaintenanceStartTimeOutput {
        crate::operation::update_maintenance_start_time::UpdateMaintenanceStartTimeOutput {
            gateway_arn: self.gateway_arn,
            _request_id: self._request_id,
        }
    }
}
