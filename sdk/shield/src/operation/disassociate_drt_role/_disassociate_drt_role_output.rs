// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateDrtRoleOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DisassociateDrtRoleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateDrtRoleOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateDrtRoleOutput`](crate::operation::disassociate_drt_role::DisassociateDrtRoleOutput).
    pub fn builder() -> crate::operation::disassociate_drt_role::builders::DisassociateDrtRoleOutputBuilder {
        crate::operation::disassociate_drt_role::builders::DisassociateDrtRoleOutputBuilder::default()
    }
}

/// A builder for [`DisassociateDrtRoleOutput`](crate::operation::disassociate_drt_role::DisassociateDrtRoleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateDrtRoleOutputBuilder {
    _request_id: Option<String>,
}
impl DisassociateDrtRoleOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateDrtRoleOutput`](crate::operation::disassociate_drt_role::DisassociateDrtRoleOutput).
    pub fn build(self) -> crate::operation::disassociate_drt_role::DisassociateDrtRoleOutput {
        crate::operation::disassociate_drt_role::DisassociateDrtRoleOutput {
            _request_id: self._request_id,
        }
    }
}
