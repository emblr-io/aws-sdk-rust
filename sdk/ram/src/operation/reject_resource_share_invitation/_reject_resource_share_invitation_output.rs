// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RejectResourceShareInvitationOutput {
    /// <p>An object that contains the details about the rejected invitation.</p>
    pub resource_share_invitation: ::std::option::Option<crate::types::ResourceShareInvitation>,
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RejectResourceShareInvitationOutput {
    /// <p>An object that contains the details about the rejected invitation.</p>
    pub fn resource_share_invitation(&self) -> ::std::option::Option<&crate::types::ResourceShareInvitation> {
        self.resource_share_invitation.as_ref()
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for RejectResourceShareInvitationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RejectResourceShareInvitationOutput {
    /// Creates a new builder-style object to manufacture [`RejectResourceShareInvitationOutput`](crate::operation::reject_resource_share_invitation::RejectResourceShareInvitationOutput).
    pub fn builder() -> crate::operation::reject_resource_share_invitation::builders::RejectResourceShareInvitationOutputBuilder {
        crate::operation::reject_resource_share_invitation::builders::RejectResourceShareInvitationOutputBuilder::default()
    }
}

/// A builder for [`RejectResourceShareInvitationOutput`](crate::operation::reject_resource_share_invitation::RejectResourceShareInvitationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RejectResourceShareInvitationOutputBuilder {
    pub(crate) resource_share_invitation: ::std::option::Option<crate::types::ResourceShareInvitation>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RejectResourceShareInvitationOutputBuilder {
    /// <p>An object that contains the details about the rejected invitation.</p>
    pub fn resource_share_invitation(mut self, input: crate::types::ResourceShareInvitation) -> Self {
        self.resource_share_invitation = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the details about the rejected invitation.</p>
    pub fn set_resource_share_invitation(mut self, input: ::std::option::Option<crate::types::ResourceShareInvitation>) -> Self {
        self.resource_share_invitation = input;
        self
    }
    /// <p>An object that contains the details about the rejected invitation.</p>
    pub fn get_resource_share_invitation(&self) -> &::std::option::Option<crate::types::ResourceShareInvitation> {
        &self.resource_share_invitation
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RejectResourceShareInvitationOutput`](crate::operation::reject_resource_share_invitation::RejectResourceShareInvitationOutput).
    pub fn build(self) -> crate::operation::reject_resource_share_invitation::RejectResourceShareInvitationOutput {
        crate::operation::reject_resource_share_invitation::RejectResourceShareInvitationOutput {
            resource_share_invitation: self.resource_share_invitation,
            client_token: self.client_token,
            _request_id: self._request_id,
        }
    }
}
