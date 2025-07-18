// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreAddressToClassicOutput {
    /// <p>The Elastic IP address.</p>
    pub public_ip: ::std::option::Option<::std::string::String>,
    /// <p>The move status for the IP address.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    _request_id: Option<String>,
}
impl RestoreAddressToClassicOutput {
    /// <p>The Elastic IP address.</p>
    pub fn public_ip(&self) -> ::std::option::Option<&str> {
        self.public_ip.as_deref()
    }
    /// <p>The move status for the IP address.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RestoreAddressToClassicOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RestoreAddressToClassicOutput {
    /// Creates a new builder-style object to manufacture [`RestoreAddressToClassicOutput`](crate::operation::restore_address_to_classic::RestoreAddressToClassicOutput).
    pub fn builder() -> crate::operation::restore_address_to_classic::builders::RestoreAddressToClassicOutputBuilder {
        crate::operation::restore_address_to_classic::builders::RestoreAddressToClassicOutputBuilder::default()
    }
}

/// A builder for [`RestoreAddressToClassicOutput`](crate::operation::restore_address_to_classic::RestoreAddressToClassicOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreAddressToClassicOutputBuilder {
    pub(crate) public_ip: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    _request_id: Option<String>,
}
impl RestoreAddressToClassicOutputBuilder {
    /// <p>The Elastic IP address.</p>
    pub fn public_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elastic IP address.</p>
    pub fn set_public_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_ip = input;
        self
    }
    /// <p>The Elastic IP address.</p>
    pub fn get_public_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_ip
    }
    /// <p>The move status for the IP address.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The move status for the IP address.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The move status for the IP address.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RestoreAddressToClassicOutput`](crate::operation::restore_address_to_classic::RestoreAddressToClassicOutput).
    pub fn build(self) -> crate::operation::restore_address_to_classic::RestoreAddressToClassicOutput {
        crate::operation::restore_address_to_classic::RestoreAddressToClassicOutput {
            public_ip: self.public_ip,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
