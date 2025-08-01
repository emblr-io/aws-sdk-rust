// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMemberOutput {
    /// <p>The properties of a member.</p>
    pub member: ::std::option::Option<crate::types::Member>,
    _request_id: Option<String>,
}
impl GetMemberOutput {
    /// <p>The properties of a member.</p>
    pub fn member(&self) -> ::std::option::Option<&crate::types::Member> {
        self.member.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetMemberOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetMemberOutput {
    /// Creates a new builder-style object to manufacture [`GetMemberOutput`](crate::operation::get_member::GetMemberOutput).
    pub fn builder() -> crate::operation::get_member::builders::GetMemberOutputBuilder {
        crate::operation::get_member::builders::GetMemberOutputBuilder::default()
    }
}

/// A builder for [`GetMemberOutput`](crate::operation::get_member::GetMemberOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMemberOutputBuilder {
    pub(crate) member: ::std::option::Option<crate::types::Member>,
    _request_id: Option<String>,
}
impl GetMemberOutputBuilder {
    /// <p>The properties of a member.</p>
    pub fn member(mut self, input: crate::types::Member) -> Self {
        self.member = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of a member.</p>
    pub fn set_member(mut self, input: ::std::option::Option<crate::types::Member>) -> Self {
        self.member = input;
        self
    }
    /// <p>The properties of a member.</p>
    pub fn get_member(&self) -> &::std::option::Option<crate::types::Member> {
        &self.member
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetMemberOutput`](crate::operation::get_member::GetMemberOutput).
    pub fn build(self) -> crate::operation::get_member::GetMemberOutput {
        crate::operation::get_member::GetMemberOutput {
            member: self.member,
            _request_id: self._request_id,
        }
    }
}
