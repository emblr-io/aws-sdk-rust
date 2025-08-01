// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTaskContactOutput {
    /// <p>The identifier of this contact within the Amazon Connect instance.</p>
    pub contact_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartTaskContactOutput {
    /// <p>The identifier of this contact within the Amazon Connect instance.</p>
    pub fn contact_id(&self) -> ::std::option::Option<&str> {
        self.contact_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartTaskContactOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartTaskContactOutput {
    /// Creates a new builder-style object to manufacture [`StartTaskContactOutput`](crate::operation::start_task_contact::StartTaskContactOutput).
    pub fn builder() -> crate::operation::start_task_contact::builders::StartTaskContactOutputBuilder {
        crate::operation::start_task_contact::builders::StartTaskContactOutputBuilder::default()
    }
}

/// A builder for [`StartTaskContactOutput`](crate::operation::start_task_contact::StartTaskContactOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTaskContactOutputBuilder {
    pub(crate) contact_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartTaskContactOutputBuilder {
    /// <p>The identifier of this contact within the Amazon Connect instance.</p>
    pub fn contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of this contact within the Amazon Connect instance.</p>
    pub fn set_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_id = input;
        self
    }
    /// <p>The identifier of this contact within the Amazon Connect instance.</p>
    pub fn get_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartTaskContactOutput`](crate::operation::start_task_contact::StartTaskContactOutput).
    pub fn build(self) -> crate::operation::start_task_contact::StartTaskContactOutput {
        crate::operation::start_task_contact::StartTaskContactOutput {
            contact_id: self.contact_id,
            _request_id: self._request_id,
        }
    }
}
