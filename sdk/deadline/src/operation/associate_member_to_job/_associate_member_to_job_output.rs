// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMemberToJobOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateMemberToJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateMemberToJobOutput {
    /// Creates a new builder-style object to manufacture [`AssociateMemberToJobOutput`](crate::operation::associate_member_to_job::AssociateMemberToJobOutput).
    pub fn builder() -> crate::operation::associate_member_to_job::builders::AssociateMemberToJobOutputBuilder {
        crate::operation::associate_member_to_job::builders::AssociateMemberToJobOutputBuilder::default()
    }
}

/// A builder for [`AssociateMemberToJobOutput`](crate::operation::associate_member_to_job::AssociateMemberToJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMemberToJobOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateMemberToJobOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateMemberToJobOutput`](crate::operation::associate_member_to_job::AssociateMemberToJobOutput).
    pub fn build(self) -> crate::operation::associate_member_to_job::AssociateMemberToJobOutput {
        crate::operation::associate_member_to_job::AssociateMemberToJobOutput {
            _request_id: self._request_id,
        }
    }
}
