// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateCollaborationOutput {
    /// <p>The entire collaboration that has been updated.</p>
    pub collaboration: ::std::option::Option<crate::types::Collaboration>,
    _request_id: Option<String>,
}
impl UpdateCollaborationOutput {
    /// <p>The entire collaboration that has been updated.</p>
    pub fn collaboration(&self) -> ::std::option::Option<&crate::types::Collaboration> {
        self.collaboration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateCollaborationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateCollaborationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateCollaborationOutput`](crate::operation::update_collaboration::UpdateCollaborationOutput).
    pub fn builder() -> crate::operation::update_collaboration::builders::UpdateCollaborationOutputBuilder {
        crate::operation::update_collaboration::builders::UpdateCollaborationOutputBuilder::default()
    }
}

/// A builder for [`UpdateCollaborationOutput`](crate::operation::update_collaboration::UpdateCollaborationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateCollaborationOutputBuilder {
    pub(crate) collaboration: ::std::option::Option<crate::types::Collaboration>,
    _request_id: Option<String>,
}
impl UpdateCollaborationOutputBuilder {
    /// <p>The entire collaboration that has been updated.</p>
    /// This field is required.
    pub fn collaboration(mut self, input: crate::types::Collaboration) -> Self {
        self.collaboration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entire collaboration that has been updated.</p>
    pub fn set_collaboration(mut self, input: ::std::option::Option<crate::types::Collaboration>) -> Self {
        self.collaboration = input;
        self
    }
    /// <p>The entire collaboration that has been updated.</p>
    pub fn get_collaboration(&self) -> &::std::option::Option<crate::types::Collaboration> {
        &self.collaboration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateCollaborationOutput`](crate::operation::update_collaboration::UpdateCollaborationOutput).
    pub fn build(self) -> crate::operation::update_collaboration::UpdateCollaborationOutput {
        crate::operation::update_collaboration::UpdateCollaborationOutput {
            collaboration: self.collaboration,
            _request_id: self._request_id,
        }
    }
}
