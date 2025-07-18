// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRequestValidatorOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteRequestValidatorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteRequestValidatorOutput {
    /// Creates a new builder-style object to manufacture [`DeleteRequestValidatorOutput`](crate::operation::delete_request_validator::DeleteRequestValidatorOutput).
    pub fn builder() -> crate::operation::delete_request_validator::builders::DeleteRequestValidatorOutputBuilder {
        crate::operation::delete_request_validator::builders::DeleteRequestValidatorOutputBuilder::default()
    }
}

/// A builder for [`DeleteRequestValidatorOutput`](crate::operation::delete_request_validator::DeleteRequestValidatorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRequestValidatorOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteRequestValidatorOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteRequestValidatorOutput`](crate::operation::delete_request_validator::DeleteRequestValidatorOutput).
    pub fn build(self) -> crate::operation::delete_request_validator::DeleteRequestValidatorOutput {
        crate::operation::delete_request_validator::DeleteRequestValidatorOutput {
            _request_id: self._request_id,
        }
    }
}
