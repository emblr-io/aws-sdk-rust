// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMemberToGroupOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateMemberToGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateMemberToGroupOutput {
    /// Creates a new builder-style object to manufacture [`AssociateMemberToGroupOutput`](crate::operation::associate_member_to_group::AssociateMemberToGroupOutput).
    pub fn builder() -> crate::operation::associate_member_to_group::builders::AssociateMemberToGroupOutputBuilder {
        crate::operation::associate_member_to_group::builders::AssociateMemberToGroupOutputBuilder::default()
    }
}

/// A builder for [`AssociateMemberToGroupOutput`](crate::operation::associate_member_to_group::AssociateMemberToGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMemberToGroupOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateMemberToGroupOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateMemberToGroupOutput`](crate::operation::associate_member_to_group::AssociateMemberToGroupOutput).
    pub fn build(self) -> crate::operation::associate_member_to_group::AssociateMemberToGroupOutput {
        crate::operation::associate_member_to_group::AssociateMemberToGroupOutput {
            _request_id: self._request_id,
        }
    }
}
