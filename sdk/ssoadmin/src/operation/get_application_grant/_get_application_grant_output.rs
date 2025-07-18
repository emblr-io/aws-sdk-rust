// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApplicationGrantOutput {
    /// <p>A structure that describes the requested grant.</p>
    pub grant: ::std::option::Option<crate::types::Grant>,
    _request_id: Option<String>,
}
impl GetApplicationGrantOutput {
    /// <p>A structure that describes the requested grant.</p>
    pub fn grant(&self) -> ::std::option::Option<&crate::types::Grant> {
        self.grant.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetApplicationGrantOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetApplicationGrantOutput {
    /// Creates a new builder-style object to manufacture [`GetApplicationGrantOutput`](crate::operation::get_application_grant::GetApplicationGrantOutput).
    pub fn builder() -> crate::operation::get_application_grant::builders::GetApplicationGrantOutputBuilder {
        crate::operation::get_application_grant::builders::GetApplicationGrantOutputBuilder::default()
    }
}

/// A builder for [`GetApplicationGrantOutput`](crate::operation::get_application_grant::GetApplicationGrantOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApplicationGrantOutputBuilder {
    pub(crate) grant: ::std::option::Option<crate::types::Grant>,
    _request_id: Option<String>,
}
impl GetApplicationGrantOutputBuilder {
    /// <p>A structure that describes the requested grant.</p>
    /// This field is required.
    pub fn grant(mut self, input: crate::types::Grant) -> Self {
        self.grant = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that describes the requested grant.</p>
    pub fn set_grant(mut self, input: ::std::option::Option<crate::types::Grant>) -> Self {
        self.grant = input;
        self
    }
    /// <p>A structure that describes the requested grant.</p>
    pub fn get_grant(&self) -> &::std::option::Option<crate::types::Grant> {
        &self.grant
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetApplicationGrantOutput`](crate::operation::get_application_grant::GetApplicationGrantOutput).
    pub fn build(self) -> crate::operation::get_application_grant::GetApplicationGrantOutput {
        crate::operation::get_application_grant::GetApplicationGrantOutput {
            grant: self.grant,
            _request_id: self._request_id,
        }
    }
}
