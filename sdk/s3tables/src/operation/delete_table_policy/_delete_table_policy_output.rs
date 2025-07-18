// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTablePolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteTablePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteTablePolicyOutput {
    /// Creates a new builder-style object to manufacture [`DeleteTablePolicyOutput`](crate::operation::delete_table_policy::DeleteTablePolicyOutput).
    pub fn builder() -> crate::operation::delete_table_policy::builders::DeleteTablePolicyOutputBuilder {
        crate::operation::delete_table_policy::builders::DeleteTablePolicyOutputBuilder::default()
    }
}

/// A builder for [`DeleteTablePolicyOutput`](crate::operation::delete_table_policy::DeleteTablePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTablePolicyOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteTablePolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteTablePolicyOutput`](crate::operation::delete_table_policy::DeleteTablePolicyOutput).
    pub fn build(self) -> crate::operation::delete_table_policy::DeleteTablePolicyOutput {
        crate::operation::delete_table_policy::DeleteTablePolicyOutput {
            _request_id: self._request_id,
        }
    }
}
