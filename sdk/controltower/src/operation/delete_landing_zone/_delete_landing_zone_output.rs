// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLandingZoneOutput {
    /// <p>&gt;A unique identifier assigned to a <code>DeleteLandingZone</code> operation. You can use this identifier as an input parameter of <code>GetLandingZoneOperation</code> to check the operation's status.</p>
    pub operation_identifier: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteLandingZoneOutput {
    /// <p>&gt;A unique identifier assigned to a <code>DeleteLandingZone</code> operation. You can use this identifier as an input parameter of <code>GetLandingZoneOperation</code> to check the operation's status.</p>
    pub fn operation_identifier(&self) -> &str {
        use std::ops::Deref;
        self.operation_identifier.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteLandingZoneOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteLandingZoneOutput {
    /// Creates a new builder-style object to manufacture [`DeleteLandingZoneOutput`](crate::operation::delete_landing_zone::DeleteLandingZoneOutput).
    pub fn builder() -> crate::operation::delete_landing_zone::builders::DeleteLandingZoneOutputBuilder {
        crate::operation::delete_landing_zone::builders::DeleteLandingZoneOutputBuilder::default()
    }
}

/// A builder for [`DeleteLandingZoneOutput`](crate::operation::delete_landing_zone::DeleteLandingZoneOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLandingZoneOutputBuilder {
    pub(crate) operation_identifier: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteLandingZoneOutputBuilder {
    /// <p>&gt;A unique identifier assigned to a <code>DeleteLandingZone</code> operation. You can use this identifier as an input parameter of <code>GetLandingZoneOperation</code> to check the operation's status.</p>
    /// This field is required.
    pub fn operation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>&gt;A unique identifier assigned to a <code>DeleteLandingZone</code> operation. You can use this identifier as an input parameter of <code>GetLandingZoneOperation</code> to check the operation's status.</p>
    pub fn set_operation_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_identifier = input;
        self
    }
    /// <p>&gt;A unique identifier assigned to a <code>DeleteLandingZone</code> operation. You can use this identifier as an input parameter of <code>GetLandingZoneOperation</code> to check the operation's status.</p>
    pub fn get_operation_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_identifier
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteLandingZoneOutput`](crate::operation::delete_landing_zone::DeleteLandingZoneOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`operation_identifier`](crate::operation::delete_landing_zone::builders::DeleteLandingZoneOutputBuilder::operation_identifier)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_landing_zone::DeleteLandingZoneOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_landing_zone::DeleteLandingZoneOutput {
            operation_identifier: self.operation_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operation_identifier",
                    "operation_identifier was not specified but it is required when building DeleteLandingZoneOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
