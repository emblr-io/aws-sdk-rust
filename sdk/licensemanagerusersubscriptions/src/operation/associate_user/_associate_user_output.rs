// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateUserOutput {
    /// <p>Metadata that describes the associate user operation.</p>
    pub instance_user_summary: ::std::option::Option<crate::types::InstanceUserSummary>,
    _request_id: Option<String>,
}
impl AssociateUserOutput {
    /// <p>Metadata that describes the associate user operation.</p>
    pub fn instance_user_summary(&self) -> ::std::option::Option<&crate::types::InstanceUserSummary> {
        self.instance_user_summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateUserOutput {
    /// Creates a new builder-style object to manufacture [`AssociateUserOutput`](crate::operation::associate_user::AssociateUserOutput).
    pub fn builder() -> crate::operation::associate_user::builders::AssociateUserOutputBuilder {
        crate::operation::associate_user::builders::AssociateUserOutputBuilder::default()
    }
}

/// A builder for [`AssociateUserOutput`](crate::operation::associate_user::AssociateUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateUserOutputBuilder {
    pub(crate) instance_user_summary: ::std::option::Option<crate::types::InstanceUserSummary>,
    _request_id: Option<String>,
}
impl AssociateUserOutputBuilder {
    /// <p>Metadata that describes the associate user operation.</p>
    /// This field is required.
    pub fn instance_user_summary(mut self, input: crate::types::InstanceUserSummary) -> Self {
        self.instance_user_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata that describes the associate user operation.</p>
    pub fn set_instance_user_summary(mut self, input: ::std::option::Option<crate::types::InstanceUserSummary>) -> Self {
        self.instance_user_summary = input;
        self
    }
    /// <p>Metadata that describes the associate user operation.</p>
    pub fn get_instance_user_summary(&self) -> &::std::option::Option<crate::types::InstanceUserSummary> {
        &self.instance_user_summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateUserOutput`](crate::operation::associate_user::AssociateUserOutput).
    pub fn build(self) -> crate::operation::associate_user::AssociateUserOutput {
        crate::operation::associate_user::AssociateUserOutput {
            instance_user_summary: self.instance_user_summary,
            _request_id: self._request_id,
        }
    }
}
