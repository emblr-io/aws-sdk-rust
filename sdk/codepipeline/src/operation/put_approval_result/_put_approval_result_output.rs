// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>PutApprovalResult</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutApprovalResultOutput {
    /// <p>The timestamp showing when the approval or rejection was submitted.</p>
    pub approved_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl PutApprovalResultOutput {
    /// <p>The timestamp showing when the approval or rejection was submitted.</p>
    pub fn approved_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.approved_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutApprovalResultOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutApprovalResultOutput {
    /// Creates a new builder-style object to manufacture [`PutApprovalResultOutput`](crate::operation::put_approval_result::PutApprovalResultOutput).
    pub fn builder() -> crate::operation::put_approval_result::builders::PutApprovalResultOutputBuilder {
        crate::operation::put_approval_result::builders::PutApprovalResultOutputBuilder::default()
    }
}

/// A builder for [`PutApprovalResultOutput`](crate::operation::put_approval_result::PutApprovalResultOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutApprovalResultOutputBuilder {
    pub(crate) approved_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl PutApprovalResultOutputBuilder {
    /// <p>The timestamp showing when the approval or rejection was submitted.</p>
    pub fn approved_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.approved_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp showing when the approval or rejection was submitted.</p>
    pub fn set_approved_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.approved_at = input;
        self
    }
    /// <p>The timestamp showing when the approval or rejection was submitted.</p>
    pub fn get_approved_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.approved_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutApprovalResultOutput`](crate::operation::put_approval_result::PutApprovalResultOutput).
    pub fn build(self) -> crate::operation::put_approval_result::PutApprovalResultOutput {
        crate::operation::put_approval_result::PutApprovalResultOutput {
            approved_at: self.approved_at,
            _request_id: self._request_id,
        }
    }
}
