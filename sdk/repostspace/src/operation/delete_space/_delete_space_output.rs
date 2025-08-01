// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSpaceOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteSpaceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteSpaceOutput {
    /// Creates a new builder-style object to manufacture [`DeleteSpaceOutput`](crate::operation::delete_space::DeleteSpaceOutput).
    pub fn builder() -> crate::operation::delete_space::builders::DeleteSpaceOutputBuilder {
        crate::operation::delete_space::builders::DeleteSpaceOutputBuilder::default()
    }
}

/// A builder for [`DeleteSpaceOutput`](crate::operation::delete_space::DeleteSpaceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSpaceOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteSpaceOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteSpaceOutput`](crate::operation::delete_space::DeleteSpaceOutput).
    pub fn build(self) -> crate::operation::delete_space::DeleteSpaceOutput {
        crate::operation::delete_space::DeleteSpaceOutput {
            _request_id: self._request_id,
        }
    }
}
