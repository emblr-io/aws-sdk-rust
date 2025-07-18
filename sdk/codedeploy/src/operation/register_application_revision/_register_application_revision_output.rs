// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterApplicationRevisionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RegisterApplicationRevisionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RegisterApplicationRevisionOutput {
    /// Creates a new builder-style object to manufacture [`RegisterApplicationRevisionOutput`](crate::operation::register_application_revision::RegisterApplicationRevisionOutput).
    pub fn builder() -> crate::operation::register_application_revision::builders::RegisterApplicationRevisionOutputBuilder {
        crate::operation::register_application_revision::builders::RegisterApplicationRevisionOutputBuilder::default()
    }
}

/// A builder for [`RegisterApplicationRevisionOutput`](crate::operation::register_application_revision::RegisterApplicationRevisionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterApplicationRevisionOutputBuilder {
    _request_id: Option<String>,
}
impl RegisterApplicationRevisionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RegisterApplicationRevisionOutput`](crate::operation::register_application_revision::RegisterApplicationRevisionOutput).
    pub fn build(self) -> crate::operation::register_application_revision::RegisterApplicationRevisionOutput {
        crate::operation::register_application_revision::RegisterApplicationRevisionOutput {
            _request_id: self._request_id,
        }
    }
}
