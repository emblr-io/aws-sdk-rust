// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output for CreateAppCookieStickinessPolicy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAppCookieStickinessPolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for CreateAppCookieStickinessPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAppCookieStickinessPolicyOutput {
    /// Creates a new builder-style object to manufacture [`CreateAppCookieStickinessPolicyOutput`](crate::operation::create_app_cookie_stickiness_policy::CreateAppCookieStickinessPolicyOutput).
    pub fn builder() -> crate::operation::create_app_cookie_stickiness_policy::builders::CreateAppCookieStickinessPolicyOutputBuilder {
        crate::operation::create_app_cookie_stickiness_policy::builders::CreateAppCookieStickinessPolicyOutputBuilder::default()
    }
}

/// A builder for [`CreateAppCookieStickinessPolicyOutput`](crate::operation::create_app_cookie_stickiness_policy::CreateAppCookieStickinessPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAppCookieStickinessPolicyOutputBuilder {
    _request_id: Option<String>,
}
impl CreateAppCookieStickinessPolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAppCookieStickinessPolicyOutput`](crate::operation::create_app_cookie_stickiness_policy::CreateAppCookieStickinessPolicyOutput).
    pub fn build(self) -> crate::operation::create_app_cookie_stickiness_policy::CreateAppCookieStickinessPolicyOutput {
        crate::operation::create_app_cookie_stickiness_policy::CreateAppCookieStickinessPolicyOutput {
            _request_id: self._request_id,
        }
    }
}
