// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAppAuthorizationOutput {
    /// <p>Contains information about an app authorization.</p>
    pub app_authorization: ::std::option::Option<crate::types::AppAuthorization>,
    _request_id: Option<String>,
}
impl GetAppAuthorizationOutput {
    /// <p>Contains information about an app authorization.</p>
    pub fn app_authorization(&self) -> ::std::option::Option<&crate::types::AppAuthorization> {
        self.app_authorization.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAppAuthorizationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAppAuthorizationOutput {
    /// Creates a new builder-style object to manufacture [`GetAppAuthorizationOutput`](crate::operation::get_app_authorization::GetAppAuthorizationOutput).
    pub fn builder() -> crate::operation::get_app_authorization::builders::GetAppAuthorizationOutputBuilder {
        crate::operation::get_app_authorization::builders::GetAppAuthorizationOutputBuilder::default()
    }
}

/// A builder for [`GetAppAuthorizationOutput`](crate::operation::get_app_authorization::GetAppAuthorizationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAppAuthorizationOutputBuilder {
    pub(crate) app_authorization: ::std::option::Option<crate::types::AppAuthorization>,
    _request_id: Option<String>,
}
impl GetAppAuthorizationOutputBuilder {
    /// <p>Contains information about an app authorization.</p>
    /// This field is required.
    pub fn app_authorization(mut self, input: crate::types::AppAuthorization) -> Self {
        self.app_authorization = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about an app authorization.</p>
    pub fn set_app_authorization(mut self, input: ::std::option::Option<crate::types::AppAuthorization>) -> Self {
        self.app_authorization = input;
        self
    }
    /// <p>Contains information about an app authorization.</p>
    pub fn get_app_authorization(&self) -> &::std::option::Option<crate::types::AppAuthorization> {
        &self.app_authorization
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAppAuthorizationOutput`](crate::operation::get_app_authorization::GetAppAuthorizationOutput).
    pub fn build(self) -> crate::operation::get_app_authorization::GetAppAuthorizationOutput {
        crate::operation::get_app_authorization::GetAppAuthorizationOutput {
            app_authorization: self.app_authorization,
            _request_id: self._request_id,
        }
    }
}
