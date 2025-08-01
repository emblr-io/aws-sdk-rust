// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeactivateTypeOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeactivateTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeactivateTypeOutput {
    /// Creates a new builder-style object to manufacture [`DeactivateTypeOutput`](crate::operation::deactivate_type::DeactivateTypeOutput).
    pub fn builder() -> crate::operation::deactivate_type::builders::DeactivateTypeOutputBuilder {
        crate::operation::deactivate_type::builders::DeactivateTypeOutputBuilder::default()
    }
}

/// A builder for [`DeactivateTypeOutput`](crate::operation::deactivate_type::DeactivateTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeactivateTypeOutputBuilder {
    _request_id: Option<String>,
}
impl DeactivateTypeOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeactivateTypeOutput`](crate::operation::deactivate_type::DeactivateTypeOutput).
    pub fn build(self) -> crate::operation::deactivate_type::DeactivateTypeOutput {
        crate::operation::deactivate_type::DeactivateTypeOutput {
            _request_id: self._request_id,
        }
    }
}
