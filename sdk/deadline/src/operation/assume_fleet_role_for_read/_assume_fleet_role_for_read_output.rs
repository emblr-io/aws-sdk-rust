// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AssumeFleetRoleForReadOutput {
    /// <p>The credentials for the fleet role.</p>
    pub credentials: ::std::option::Option<crate::types::AwsCredentials>,
    _request_id: Option<String>,
}
impl AssumeFleetRoleForReadOutput {
    /// <p>The credentials for the fleet role.</p>
    pub fn credentials(&self) -> ::std::option::Option<&crate::types::AwsCredentials> {
        self.credentials.as_ref()
    }
}
impl ::std::fmt::Debug for AssumeFleetRoleForReadOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AssumeFleetRoleForReadOutput");
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for AssumeFleetRoleForReadOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssumeFleetRoleForReadOutput {
    /// Creates a new builder-style object to manufacture [`AssumeFleetRoleForReadOutput`](crate::operation::assume_fleet_role_for_read::AssumeFleetRoleForReadOutput).
    pub fn builder() -> crate::operation::assume_fleet_role_for_read::builders::AssumeFleetRoleForReadOutputBuilder {
        crate::operation::assume_fleet_role_for_read::builders::AssumeFleetRoleForReadOutputBuilder::default()
    }
}

/// A builder for [`AssumeFleetRoleForReadOutput`](crate::operation::assume_fleet_role_for_read::AssumeFleetRoleForReadOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AssumeFleetRoleForReadOutputBuilder {
    pub(crate) credentials: ::std::option::Option<crate::types::AwsCredentials>,
    _request_id: Option<String>,
}
impl AssumeFleetRoleForReadOutputBuilder {
    /// <p>The credentials for the fleet role.</p>
    /// This field is required.
    pub fn credentials(mut self, input: crate::types::AwsCredentials) -> Self {
        self.credentials = ::std::option::Option::Some(input);
        self
    }
    /// <p>The credentials for the fleet role.</p>
    pub fn set_credentials(mut self, input: ::std::option::Option<crate::types::AwsCredentials>) -> Self {
        self.credentials = input;
        self
    }
    /// <p>The credentials for the fleet role.</p>
    pub fn get_credentials(&self) -> &::std::option::Option<crate::types::AwsCredentials> {
        &self.credentials
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssumeFleetRoleForReadOutput`](crate::operation::assume_fleet_role_for_read::AssumeFleetRoleForReadOutput).
    pub fn build(self) -> crate::operation::assume_fleet_role_for_read::AssumeFleetRoleForReadOutput {
        crate::operation::assume_fleet_role_for_read::AssumeFleetRoleForReadOutput {
            credentials: self.credentials,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for AssumeFleetRoleForReadOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AssumeFleetRoleForReadOutputBuilder");
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
