// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLabelOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteLabelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteLabelOutput {
    /// Creates a new builder-style object to manufacture [`DeleteLabelOutput`](crate::operation::delete_label::DeleteLabelOutput).
    pub fn builder() -> crate::operation::delete_label::builders::DeleteLabelOutputBuilder {
        crate::operation::delete_label::builders::DeleteLabelOutputBuilder::default()
    }
}

/// A builder for [`DeleteLabelOutput`](crate::operation::delete_label::DeleteLabelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLabelOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteLabelOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteLabelOutput`](crate::operation::delete_label::DeleteLabelOutput).
    pub fn build(self) -> crate::operation::delete_label::DeleteLabelOutput {
        crate::operation::delete_label::DeleteLabelOutput {
            _request_id: self._request_id,
        }
    }
}
