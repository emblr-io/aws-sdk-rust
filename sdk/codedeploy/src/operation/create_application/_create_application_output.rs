// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>CreateApplication</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApplicationOutput {
    /// <p>A unique application ID.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateApplicationOutput {
    /// <p>A unique application ID.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateApplicationOutput {
    /// Creates a new builder-style object to manufacture [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn builder() -> crate::operation::create_application::builders::CreateApplicationOutputBuilder {
        crate::operation::create_application::builders::CreateApplicationOutputBuilder::default()
    }
}

/// A builder for [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApplicationOutputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateApplicationOutputBuilder {
    /// <p>A unique application ID.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique application ID.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>A unique application ID.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn build(self) -> crate::operation::create_application::CreateApplicationOutput {
        crate::operation::create_application::CreateApplicationOutput {
            application_id: self.application_id,
            _request_id: self._request_id,
        }
    }
}
