// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the response from the server for the request to update user attributes as an administrator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AdminUpdateUserAttributesOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AdminUpdateUserAttributesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AdminUpdateUserAttributesOutput {
    /// Creates a new builder-style object to manufacture [`AdminUpdateUserAttributesOutput`](crate::operation::admin_update_user_attributes::AdminUpdateUserAttributesOutput).
    pub fn builder() -> crate::operation::admin_update_user_attributes::builders::AdminUpdateUserAttributesOutputBuilder {
        crate::operation::admin_update_user_attributes::builders::AdminUpdateUserAttributesOutputBuilder::default()
    }
}

/// A builder for [`AdminUpdateUserAttributesOutput`](crate::operation::admin_update_user_attributes::AdminUpdateUserAttributesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AdminUpdateUserAttributesOutputBuilder {
    _request_id: Option<String>,
}
impl AdminUpdateUserAttributesOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AdminUpdateUserAttributesOutput`](crate::operation::admin_update_user_attributes::AdminUpdateUserAttributesOutput).
    pub fn build(self) -> crate::operation::admin_update_user_attributes::AdminUpdateUserAttributesOutput {
        crate::operation::admin_update_user_attributes::AdminUpdateUserAttributesOutput {
            _request_id: self._request_id,
        }
    }
}
