// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableFederationOutput {
    /// <p>The ARN of the event data store for which you enabled Lake query federation.</p>
    pub event_data_store_arn: ::std::option::Option<::std::string::String>,
    /// <p>The federation status.</p>
    pub federation_status: ::std::option::Option<crate::types::FederationStatus>,
    /// <p>The ARN of the federation role.</p>
    pub federation_role_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl EnableFederationOutput {
    /// <p>The ARN of the event data store for which you enabled Lake query federation.</p>
    pub fn event_data_store_arn(&self) -> ::std::option::Option<&str> {
        self.event_data_store_arn.as_deref()
    }
    /// <p>The federation status.</p>
    pub fn federation_status(&self) -> ::std::option::Option<&crate::types::FederationStatus> {
        self.federation_status.as_ref()
    }
    /// <p>The ARN of the federation role.</p>
    pub fn federation_role_arn(&self) -> ::std::option::Option<&str> {
        self.federation_role_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for EnableFederationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl EnableFederationOutput {
    /// Creates a new builder-style object to manufacture [`EnableFederationOutput`](crate::operation::enable_federation::EnableFederationOutput).
    pub fn builder() -> crate::operation::enable_federation::builders::EnableFederationOutputBuilder {
        crate::operation::enable_federation::builders::EnableFederationOutputBuilder::default()
    }
}

/// A builder for [`EnableFederationOutput`](crate::operation::enable_federation::EnableFederationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableFederationOutputBuilder {
    pub(crate) event_data_store_arn: ::std::option::Option<::std::string::String>,
    pub(crate) federation_status: ::std::option::Option<crate::types::FederationStatus>,
    pub(crate) federation_role_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl EnableFederationOutputBuilder {
    /// <p>The ARN of the event data store for which you enabled Lake query federation.</p>
    pub fn event_data_store_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the event data store for which you enabled Lake query federation.</p>
    pub fn set_event_data_store_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store_arn = input;
        self
    }
    /// <p>The ARN of the event data store for which you enabled Lake query federation.</p>
    pub fn get_event_data_store_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store_arn
    }
    /// <p>The federation status.</p>
    pub fn federation_status(mut self, input: crate::types::FederationStatus) -> Self {
        self.federation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The federation status.</p>
    pub fn set_federation_status(mut self, input: ::std::option::Option<crate::types::FederationStatus>) -> Self {
        self.federation_status = input;
        self
    }
    /// <p>The federation status.</p>
    pub fn get_federation_status(&self) -> &::std::option::Option<crate::types::FederationStatus> {
        &self.federation_status
    }
    /// <p>The ARN of the federation role.</p>
    pub fn federation_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.federation_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the federation role.</p>
    pub fn set_federation_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.federation_role_arn = input;
        self
    }
    /// <p>The ARN of the federation role.</p>
    pub fn get_federation_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.federation_role_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`EnableFederationOutput`](crate::operation::enable_federation::EnableFederationOutput).
    pub fn build(self) -> crate::operation::enable_federation::EnableFederationOutput {
        crate::operation::enable_federation::EnableFederationOutput {
            event_data_store_arn: self.event_data_store_arn,
            federation_status: self.federation_status,
            federation_role_arn: self.federation_role_arn,
            _request_id: self._request_id,
        }
    }
}
