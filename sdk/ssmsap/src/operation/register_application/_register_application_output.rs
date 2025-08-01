// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterApplicationOutput {
    /// <p>The application registered with AWS Systems Manager for SAP.</p>
    pub application: ::std::option::Option<crate::types::Application>,
    /// <p>The ID of the operation.</p>
    pub operation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RegisterApplicationOutput {
    /// <p>The application registered with AWS Systems Manager for SAP.</p>
    pub fn application(&self) -> ::std::option::Option<&crate::types::Application> {
        self.application.as_ref()
    }
    /// <p>The ID of the operation.</p>
    pub fn operation_id(&self) -> ::std::option::Option<&str> {
        self.operation_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for RegisterApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RegisterApplicationOutput {
    /// Creates a new builder-style object to manufacture [`RegisterApplicationOutput`](crate::operation::register_application::RegisterApplicationOutput).
    pub fn builder() -> crate::operation::register_application::builders::RegisterApplicationOutputBuilder {
        crate::operation::register_application::builders::RegisterApplicationOutputBuilder::default()
    }
}

/// A builder for [`RegisterApplicationOutput`](crate::operation::register_application::RegisterApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterApplicationOutputBuilder {
    pub(crate) application: ::std::option::Option<crate::types::Application>,
    pub(crate) operation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RegisterApplicationOutputBuilder {
    /// <p>The application registered with AWS Systems Manager for SAP.</p>
    pub fn application(mut self, input: crate::types::Application) -> Self {
        self.application = ::std::option::Option::Some(input);
        self
    }
    /// <p>The application registered with AWS Systems Manager for SAP.</p>
    pub fn set_application(mut self, input: ::std::option::Option<crate::types::Application>) -> Self {
        self.application = input;
        self
    }
    /// <p>The application registered with AWS Systems Manager for SAP.</p>
    pub fn get_application(&self) -> &::std::option::Option<crate::types::Application> {
        &self.application
    }
    /// <p>The ID of the operation.</p>
    pub fn operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the operation.</p>
    pub fn set_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_id = input;
        self
    }
    /// <p>The ID of the operation.</p>
    pub fn get_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RegisterApplicationOutput`](crate::operation::register_application::RegisterApplicationOutput).
    pub fn build(self) -> crate::operation::register_application::RegisterApplicationOutput {
        crate::operation::register_application::RegisterApplicationOutput {
            application: self.application,
            operation_id: self.operation_id,
            _request_id: self._request_id,
        }
    }
}
