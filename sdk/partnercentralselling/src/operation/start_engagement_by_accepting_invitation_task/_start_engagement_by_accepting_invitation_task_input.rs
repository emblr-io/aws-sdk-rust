// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartEngagementByAcceptingInvitationTaskInput {
    /// <p>Specifies the catalog related to the task. Use <code>AWS</code> for production engagements and <code>Sandbox</code> for testing scenarios.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier provided by the client that helps to ensure the idempotency of the request. This can be a random or meaningful string but must be unique for each request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the unique identifier of the <code>EngagementInvitation</code> to be accepted. Providing the correct identifier helps ensure that the correct engagement is processed.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>A map of the key-value pairs of the tag or tags to assign.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl StartEngagementByAcceptingInvitationTaskInput {
    /// <p>Specifies the catalog related to the task. Use <code>AWS</code> for production engagements and <code>Sandbox</code> for testing scenarios.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>A unique, case-sensitive identifier provided by the client that helps to ensure the idempotency of the request. This can be a random or meaningful string but must be unique for each request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Specifies the unique identifier of the <code>EngagementInvitation</code> to be accepted. Providing the correct identifier helps ensure that the correct engagement is processed.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl StartEngagementByAcceptingInvitationTaskInput {
    /// Creates a new builder-style object to manufacture [`StartEngagementByAcceptingInvitationTaskInput`](crate::operation::start_engagement_by_accepting_invitation_task::StartEngagementByAcceptingInvitationTaskInput).
    pub fn builder() -> crate::operation::start_engagement_by_accepting_invitation_task::builders::StartEngagementByAcceptingInvitationTaskInputBuilder
    {
        crate::operation::start_engagement_by_accepting_invitation_task::builders::StartEngagementByAcceptingInvitationTaskInputBuilder::default()
    }
}

/// A builder for [`StartEngagementByAcceptingInvitationTaskInput`](crate::operation::start_engagement_by_accepting_invitation_task::StartEngagementByAcceptingInvitationTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartEngagementByAcceptingInvitationTaskInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl StartEngagementByAcceptingInvitationTaskInputBuilder {
    /// <p>Specifies the catalog related to the task. Use <code>AWS</code> for production engagements and <code>Sandbox</code> for testing scenarios.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog related to the task. Use <code>AWS</code> for production engagements and <code>Sandbox</code> for testing scenarios.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog related to the task. Use <code>AWS</code> for production engagements and <code>Sandbox</code> for testing scenarios.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>A unique, case-sensitive identifier provided by the client that helps to ensure the idempotency of the request. This can be a random or meaningful string but must be unique for each request.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier provided by the client that helps to ensure the idempotency of the request. This can be a random or meaningful string but must be unique for each request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier provided by the client that helps to ensure the idempotency of the request. This can be a random or meaningful string but must be unique for each request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Specifies the unique identifier of the <code>EngagementInvitation</code> to be accepted. Providing the correct identifier helps ensure that the correct engagement is processed.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the unique identifier of the <code>EngagementInvitation</code> to be accepted. Providing the correct identifier helps ensure that the correct engagement is processed.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>Specifies the unique identifier of the <code>EngagementInvitation</code> to be accepted. Providing the correct identifier helps ensure that the correct engagement is processed.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map of the key-value pairs of the tag or tags to assign.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`StartEngagementByAcceptingInvitationTaskInput`](crate::operation::start_engagement_by_accepting_invitation_task::StartEngagementByAcceptingInvitationTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_engagement_by_accepting_invitation_task::StartEngagementByAcceptingInvitationTaskInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_engagement_by_accepting_invitation_task::StartEngagementByAcceptingInvitationTaskInput {
                catalog: self.catalog,
                client_token: self.client_token,
                identifier: self.identifier,
                tags: self.tags,
            },
        )
    }
}
