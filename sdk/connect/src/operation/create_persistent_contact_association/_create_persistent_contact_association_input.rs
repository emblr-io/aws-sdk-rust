// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePersistentContactAssociationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>This is the contactId of the current contact that the <code>CreatePersistentContactAssociation</code> API is being called from.</p>
    pub initial_contact_id: ::std::option::Option<::std::string::String>,
    /// <p>The contactId chosen for rehydration depends on the type chosen.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENTIRE_PAST_SESSION</code>: Rehydrates a chat from the most recently terminated past chat contact of the specified past ended chat session. To use this type, provide the <code>initialContactId</code> of the past ended chat session in the <code>sourceContactId</code> field. In this type, Amazon Connect determines what the most recent chat contact on the past ended chat session and uses it to start a persistent chat.</p></li>
    /// <li>
    /// <p><code>FROM_SEGMENT</code>: Rehydrates a chat from the specified past chat contact provided in the <code>sourceContactId</code> field.</p></li>
    /// </ul>
    /// <p>The actual contactId used for rehydration is provided in the response of this API.</p>
    /// <p>To illustrate how to use rehydration type, consider the following example: A customer starts a chat session. Agent a1 accepts the chat and a conversation starts between the customer and Agent a1. This first contact creates a contact ID <b>C1</b>. Agent a1 then transfers the chat to Agent a2. This creates another contact ID <b>C2</b>. At this point Agent a2 ends the chat. The customer is forwarded to the disconnect flow for a post chat survey that creates another contact ID <b>C3</b>. After the chat survey, the chat session ends. Later, the customer returns and wants to resume their past chat session. At this point, the customer can have following use cases:</p>
    /// <ul>
    /// <li>
    /// <p><b>Use Case 1</b>: The customer wants to continue the past chat session but they want to hide the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C2"</p></li>
    /// <li>
    /// <p>RehydrationType = "FROM_SEGMENT"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the specified past ended contact (C2). Transcripts of past chat sessions C2 and C1 are accessible in the current persistent chat session. Note that chat segment C3 is dropped from the persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Use Case 2</b>: The customer wants to continue the past chat session and see the transcript of the entire past engagement, including the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C1"</p></li>
    /// <li>
    /// <p>RehydrationType = "ENTIRE_PAST_SESSION"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the most recently ended chat contact (C3). Transcripts of past chat sessions C3, C2 and C1 are accessible in the current persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub rehydration_type: ::std::option::Option<crate::types::RehydrationType>,
    /// <p>The contactId from which a persistent chat session must be started.</p>
    pub source_contact_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreatePersistentContactAssociationInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>This is the contactId of the current contact that the <code>CreatePersistentContactAssociation</code> API is being called from.</p>
    pub fn initial_contact_id(&self) -> ::std::option::Option<&str> {
        self.initial_contact_id.as_deref()
    }
    /// <p>The contactId chosen for rehydration depends on the type chosen.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENTIRE_PAST_SESSION</code>: Rehydrates a chat from the most recently terminated past chat contact of the specified past ended chat session. To use this type, provide the <code>initialContactId</code> of the past ended chat session in the <code>sourceContactId</code> field. In this type, Amazon Connect determines what the most recent chat contact on the past ended chat session and uses it to start a persistent chat.</p></li>
    /// <li>
    /// <p><code>FROM_SEGMENT</code>: Rehydrates a chat from the specified past chat contact provided in the <code>sourceContactId</code> field.</p></li>
    /// </ul>
    /// <p>The actual contactId used for rehydration is provided in the response of this API.</p>
    /// <p>To illustrate how to use rehydration type, consider the following example: A customer starts a chat session. Agent a1 accepts the chat and a conversation starts between the customer and Agent a1. This first contact creates a contact ID <b>C1</b>. Agent a1 then transfers the chat to Agent a2. This creates another contact ID <b>C2</b>. At this point Agent a2 ends the chat. The customer is forwarded to the disconnect flow for a post chat survey that creates another contact ID <b>C3</b>. After the chat survey, the chat session ends. Later, the customer returns and wants to resume their past chat session. At this point, the customer can have following use cases:</p>
    /// <ul>
    /// <li>
    /// <p><b>Use Case 1</b>: The customer wants to continue the past chat session but they want to hide the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C2"</p></li>
    /// <li>
    /// <p>RehydrationType = "FROM_SEGMENT"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the specified past ended contact (C2). Transcripts of past chat sessions C2 and C1 are accessible in the current persistent chat session. Note that chat segment C3 is dropped from the persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Use Case 2</b>: The customer wants to continue the past chat session and see the transcript of the entire past engagement, including the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C1"</p></li>
    /// <li>
    /// <p>RehydrationType = "ENTIRE_PAST_SESSION"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the most recently ended chat contact (C3). Transcripts of past chat sessions C3, C2 and C1 are accessible in the current persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn rehydration_type(&self) -> ::std::option::Option<&crate::types::RehydrationType> {
        self.rehydration_type.as_ref()
    }
    /// <p>The contactId from which a persistent chat session must be started.</p>
    pub fn source_contact_id(&self) -> ::std::option::Option<&str> {
        self.source_contact_id.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreatePersistentContactAssociationInput {
    /// Creates a new builder-style object to manufacture [`CreatePersistentContactAssociationInput`](crate::operation::create_persistent_contact_association::CreatePersistentContactAssociationInput).
    pub fn builder() -> crate::operation::create_persistent_contact_association::builders::CreatePersistentContactAssociationInputBuilder {
        crate::operation::create_persistent_contact_association::builders::CreatePersistentContactAssociationInputBuilder::default()
    }
}

/// A builder for [`CreatePersistentContactAssociationInput`](crate::operation::create_persistent_contact_association::CreatePersistentContactAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePersistentContactAssociationInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) initial_contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) rehydration_type: ::std::option::Option<crate::types::RehydrationType>,
    pub(crate) source_contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreatePersistentContactAssociationInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>This is the contactId of the current contact that the <code>CreatePersistentContactAssociation</code> API is being called from.</p>
    /// This field is required.
    pub fn initial_contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initial_contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is the contactId of the current contact that the <code>CreatePersistentContactAssociation</code> API is being called from.</p>
    pub fn set_initial_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initial_contact_id = input;
        self
    }
    /// <p>This is the contactId of the current contact that the <code>CreatePersistentContactAssociation</code> API is being called from.</p>
    pub fn get_initial_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.initial_contact_id
    }
    /// <p>The contactId chosen for rehydration depends on the type chosen.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENTIRE_PAST_SESSION</code>: Rehydrates a chat from the most recently terminated past chat contact of the specified past ended chat session. To use this type, provide the <code>initialContactId</code> of the past ended chat session in the <code>sourceContactId</code> field. In this type, Amazon Connect determines what the most recent chat contact on the past ended chat session and uses it to start a persistent chat.</p></li>
    /// <li>
    /// <p><code>FROM_SEGMENT</code>: Rehydrates a chat from the specified past chat contact provided in the <code>sourceContactId</code> field.</p></li>
    /// </ul>
    /// <p>The actual contactId used for rehydration is provided in the response of this API.</p>
    /// <p>To illustrate how to use rehydration type, consider the following example: A customer starts a chat session. Agent a1 accepts the chat and a conversation starts between the customer and Agent a1. This first contact creates a contact ID <b>C1</b>. Agent a1 then transfers the chat to Agent a2. This creates another contact ID <b>C2</b>. At this point Agent a2 ends the chat. The customer is forwarded to the disconnect flow for a post chat survey that creates another contact ID <b>C3</b>. After the chat survey, the chat session ends. Later, the customer returns and wants to resume their past chat session. At this point, the customer can have following use cases:</p>
    /// <ul>
    /// <li>
    /// <p><b>Use Case 1</b>: The customer wants to continue the past chat session but they want to hide the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C2"</p></li>
    /// <li>
    /// <p>RehydrationType = "FROM_SEGMENT"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the specified past ended contact (C2). Transcripts of past chat sessions C2 and C1 are accessible in the current persistent chat session. Note that chat segment C3 is dropped from the persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Use Case 2</b>: The customer wants to continue the past chat session and see the transcript of the entire past engagement, including the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C1"</p></li>
    /// <li>
    /// <p>RehydrationType = "ENTIRE_PAST_SESSION"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the most recently ended chat contact (C3). Transcripts of past chat sessions C3, C2 and C1 are accessible in the current persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    /// This field is required.
    pub fn rehydration_type(mut self, input: crate::types::RehydrationType) -> Self {
        self.rehydration_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The contactId chosen for rehydration depends on the type chosen.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENTIRE_PAST_SESSION</code>: Rehydrates a chat from the most recently terminated past chat contact of the specified past ended chat session. To use this type, provide the <code>initialContactId</code> of the past ended chat session in the <code>sourceContactId</code> field. In this type, Amazon Connect determines what the most recent chat contact on the past ended chat session and uses it to start a persistent chat.</p></li>
    /// <li>
    /// <p><code>FROM_SEGMENT</code>: Rehydrates a chat from the specified past chat contact provided in the <code>sourceContactId</code> field.</p></li>
    /// </ul>
    /// <p>The actual contactId used for rehydration is provided in the response of this API.</p>
    /// <p>To illustrate how to use rehydration type, consider the following example: A customer starts a chat session. Agent a1 accepts the chat and a conversation starts between the customer and Agent a1. This first contact creates a contact ID <b>C1</b>. Agent a1 then transfers the chat to Agent a2. This creates another contact ID <b>C2</b>. At this point Agent a2 ends the chat. The customer is forwarded to the disconnect flow for a post chat survey that creates another contact ID <b>C3</b>. After the chat survey, the chat session ends. Later, the customer returns and wants to resume their past chat session. At this point, the customer can have following use cases:</p>
    /// <ul>
    /// <li>
    /// <p><b>Use Case 1</b>: The customer wants to continue the past chat session but they want to hide the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C2"</p></li>
    /// <li>
    /// <p>RehydrationType = "FROM_SEGMENT"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the specified past ended contact (C2). Transcripts of past chat sessions C2 and C1 are accessible in the current persistent chat session. Note that chat segment C3 is dropped from the persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Use Case 2</b>: The customer wants to continue the past chat session and see the transcript of the entire past engagement, including the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C1"</p></li>
    /// <li>
    /// <p>RehydrationType = "ENTIRE_PAST_SESSION"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the most recently ended chat contact (C3). Transcripts of past chat sessions C3, C2 and C1 are accessible in the current persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn set_rehydration_type(mut self, input: ::std::option::Option<crate::types::RehydrationType>) -> Self {
        self.rehydration_type = input;
        self
    }
    /// <p>The contactId chosen for rehydration depends on the type chosen.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENTIRE_PAST_SESSION</code>: Rehydrates a chat from the most recently terminated past chat contact of the specified past ended chat session. To use this type, provide the <code>initialContactId</code> of the past ended chat session in the <code>sourceContactId</code> field. In this type, Amazon Connect determines what the most recent chat contact on the past ended chat session and uses it to start a persistent chat.</p></li>
    /// <li>
    /// <p><code>FROM_SEGMENT</code>: Rehydrates a chat from the specified past chat contact provided in the <code>sourceContactId</code> field.</p></li>
    /// </ul>
    /// <p>The actual contactId used for rehydration is provided in the response of this API.</p>
    /// <p>To illustrate how to use rehydration type, consider the following example: A customer starts a chat session. Agent a1 accepts the chat and a conversation starts between the customer and Agent a1. This first contact creates a contact ID <b>C1</b>. Agent a1 then transfers the chat to Agent a2. This creates another contact ID <b>C2</b>. At this point Agent a2 ends the chat. The customer is forwarded to the disconnect flow for a post chat survey that creates another contact ID <b>C3</b>. After the chat survey, the chat session ends. Later, the customer returns and wants to resume their past chat session. At this point, the customer can have following use cases:</p>
    /// <ul>
    /// <li>
    /// <p><b>Use Case 1</b>: The customer wants to continue the past chat session but they want to hide the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C2"</p></li>
    /// <li>
    /// <p>RehydrationType = "FROM_SEGMENT"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the specified past ended contact (C2). Transcripts of past chat sessions C2 and C1 are accessible in the current persistent chat session. Note that chat segment C3 is dropped from the persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Use Case 2</b>: The customer wants to continue the past chat session and see the transcript of the entire past engagement, including the post chat survey. For this they will use the following configuration:</p>
    /// <ul>
    /// <li>
    /// <p><b>Configuration</b></p>
    /// <ul>
    /// <li>
    /// <p>SourceContactId = "C1"</p></li>
    /// <li>
    /// <p>RehydrationType = "ENTIRE_PAST_SESSION"</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Expected behavior</b></p>
    /// <ul>
    /// <li>
    /// <p>This starts a persistent chat session from the most recently ended chat contact (C3). Transcripts of past chat sessions C3, C2 and C1 are accessible in the current persistent chat session.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn get_rehydration_type(&self) -> &::std::option::Option<crate::types::RehydrationType> {
        &self.rehydration_type
    }
    /// <p>The contactId from which a persistent chat session must be started.</p>
    /// This field is required.
    pub fn source_contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contactId from which a persistent chat session must be started.</p>
    pub fn set_source_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_contact_id = input;
        self
    }
    /// <p>The contactId from which a persistent chat session must be started.</p>
    pub fn get_source_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_contact_id
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreatePersistentContactAssociationInput`](crate::operation::create_persistent_contact_association::CreatePersistentContactAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_persistent_contact_association::CreatePersistentContactAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_persistent_contact_association::CreatePersistentContactAssociationInput {
                instance_id: self.instance_id,
                initial_contact_id: self.initial_contact_id,
                rehydration_type: self.rehydration_type,
                source_contact_id: self.source_contact_id,
                client_token: self.client_token,
            },
        )
    }
}
