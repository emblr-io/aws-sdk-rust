// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateShareOutput {
    /// <p>The ID that HealthOmics generates for the share.</p>
    pub share_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the share.</p>
    pub status: ::std::option::Option<crate::types::ShareStatus>,
    /// <p>The name of the share.</p>
    pub share_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateShareOutput {
    /// <p>The ID that HealthOmics generates for the share.</p>
    pub fn share_id(&self) -> ::std::option::Option<&str> {
        self.share_id.as_deref()
    }
    /// <p>The status of the share.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ShareStatus> {
        self.status.as_ref()
    }
    /// <p>The name of the share.</p>
    pub fn share_name(&self) -> ::std::option::Option<&str> {
        self.share_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateShareOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateShareOutput {
    /// Creates a new builder-style object to manufacture [`CreateShareOutput`](crate::operation::create_share::CreateShareOutput).
    pub fn builder() -> crate::operation::create_share::builders::CreateShareOutputBuilder {
        crate::operation::create_share::builders::CreateShareOutputBuilder::default()
    }
}

/// A builder for [`CreateShareOutput`](crate::operation::create_share::CreateShareOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateShareOutputBuilder {
    pub(crate) share_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ShareStatus>,
    pub(crate) share_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateShareOutputBuilder {
    /// <p>The ID that HealthOmics generates for the share.</p>
    pub fn share_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.share_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID that HealthOmics generates for the share.</p>
    pub fn set_share_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.share_id = input;
        self
    }
    /// <p>The ID that HealthOmics generates for the share.</p>
    pub fn get_share_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.share_id
    }
    /// <p>The status of the share.</p>
    pub fn status(mut self, input: crate::types::ShareStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the share.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ShareStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the share.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ShareStatus> {
        &self.status
    }
    /// <p>The name of the share.</p>
    pub fn share_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.share_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the share.</p>
    pub fn set_share_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.share_name = input;
        self
    }
    /// <p>The name of the share.</p>
    pub fn get_share_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.share_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateShareOutput`](crate::operation::create_share::CreateShareOutput).
    pub fn build(self) -> crate::operation::create_share::CreateShareOutput {
        crate::operation::create_share::CreateShareOutput {
            share_id: self.share_id,
            status: self.status,
            share_name: self.share_name,
            _request_id: self._request_id,
        }
    }
}
