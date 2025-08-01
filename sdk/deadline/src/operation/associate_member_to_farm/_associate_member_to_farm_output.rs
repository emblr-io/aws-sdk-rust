// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMemberToFarmOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateMemberToFarmOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateMemberToFarmOutput {
    /// Creates a new builder-style object to manufacture [`AssociateMemberToFarmOutput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmOutput).
    pub fn builder() -> crate::operation::associate_member_to_farm::builders::AssociateMemberToFarmOutputBuilder {
        crate::operation::associate_member_to_farm::builders::AssociateMemberToFarmOutputBuilder::default()
    }
}

/// A builder for [`AssociateMemberToFarmOutput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMemberToFarmOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateMemberToFarmOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateMemberToFarmOutput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmOutput).
    pub fn build(self) -> crate::operation::associate_member_to_farm::AssociateMemberToFarmOutput {
        crate::operation::associate_member_to_farm::AssociateMemberToFarmOutput {
            _request_id: self._request_id,
        }
    }
}
