// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEngagementInvitationsInput {
    /// <p>Specifies the catalog from which to list the engagement invitations. Use <code>AWS</code> for production invitations or <code>Sandbox</code> for testing environments.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the maximum number of engagement invitations to return in the response. If more results are available, a pagination token will be provided.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A pagination token used to retrieve additional pages of results when the response to a previous request was truncated. Pass this token to continue listing invitations from where the previous call left off.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the sorting options for listing engagement invitations. Invitations can be sorted by fields such as <code>InvitationDate</code> or <code>Status</code> to help partners view results in their preferred order.</p>
    pub sort: ::std::option::Option<crate::types::OpportunityEngagementInvitationSort>,
    /// <p>Defines the type of payload associated with the engagement invitations to be listed. The attributes in this payload help decide on acceptance or rejection of the invitation.</p>
    pub payload_type: ::std::option::Option<::std::vec::Vec<crate::types::EngagementInvitationPayloadType>>,
    /// <p>Specifies the type of participant for which to list engagement invitations. Identifies the role of the participant.</p>
    pub participant_type: ::std::option::Option<crate::types::ParticipantType>,
    /// <p>Status values to filter the invitations.</p>
    pub status: ::std::option::Option<::std::vec::Vec<crate::types::InvitationStatus>>,
    /// <p>Retrieves a list of engagement invitation summaries based on specified filters. The ListEngagementInvitations operation allows you to view all invitations that you have sent or received. You must specify the ParticipantType to filter invitations where you are either the SENDER or the RECEIVER. Invitations will automatically expire if not accepted within 15 days.</p>
    pub engagement_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>List of sender AWS account IDs to filter the invitations.</p>
    pub sender_aws_account_id: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListEngagementInvitationsInput {
    /// <p>Specifies the catalog from which to list the engagement invitations. Use <code>AWS</code> for production invitations or <code>Sandbox</code> for testing environments.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>Specifies the maximum number of engagement invitations to return in the response. If more results are available, a pagination token will be provided.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A pagination token used to retrieve additional pages of results when the response to a previous request was truncated. Pass this token to continue listing invitations from where the previous call left off.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specifies the sorting options for listing engagement invitations. Invitations can be sorted by fields such as <code>InvitationDate</code> or <code>Status</code> to help partners view results in their preferred order.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::OpportunityEngagementInvitationSort> {
        self.sort.as_ref()
    }
    /// <p>Defines the type of payload associated with the engagement invitations to be listed. The attributes in this payload help decide on acceptance or rejection of the invitation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.payload_type.is_none()`.
    pub fn payload_type(&self) -> &[crate::types::EngagementInvitationPayloadType] {
        self.payload_type.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the type of participant for which to list engagement invitations. Identifies the role of the participant.</p>
    pub fn participant_type(&self) -> ::std::option::Option<&crate::types::ParticipantType> {
        self.participant_type.as_ref()
    }
    /// <p>Status values to filter the invitations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.status.is_none()`.
    pub fn status(&self) -> &[crate::types::InvitationStatus] {
        self.status.as_deref().unwrap_or_default()
    }
    /// <p>Retrieves a list of engagement invitation summaries based on specified filters. The ListEngagementInvitations operation allows you to view all invitations that you have sent or received. You must specify the ParticipantType to filter invitations where you are either the SENDER or the RECEIVER. Invitations will automatically expire if not accepted within 15 days.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.engagement_identifier.is_none()`.
    pub fn engagement_identifier(&self) -> &[::std::string::String] {
        self.engagement_identifier.as_deref().unwrap_or_default()
    }
    /// <p>List of sender AWS account IDs to filter the invitations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sender_aws_account_id.is_none()`.
    pub fn sender_aws_account_id(&self) -> &[::std::string::String] {
        self.sender_aws_account_id.as_deref().unwrap_or_default()
    }
}
impl ListEngagementInvitationsInput {
    /// Creates a new builder-style object to manufacture [`ListEngagementInvitationsInput`](crate::operation::list_engagement_invitations::ListEngagementInvitationsInput).
    pub fn builder() -> crate::operation::list_engagement_invitations::builders::ListEngagementInvitationsInputBuilder {
        crate::operation::list_engagement_invitations::builders::ListEngagementInvitationsInputBuilder::default()
    }
}

/// A builder for [`ListEngagementInvitationsInput`](crate::operation::list_engagement_invitations::ListEngagementInvitationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEngagementInvitationsInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sort: ::std::option::Option<crate::types::OpportunityEngagementInvitationSort>,
    pub(crate) payload_type: ::std::option::Option<::std::vec::Vec<crate::types::EngagementInvitationPayloadType>>,
    pub(crate) participant_type: ::std::option::Option<crate::types::ParticipantType>,
    pub(crate) status: ::std::option::Option<::std::vec::Vec<crate::types::InvitationStatus>>,
    pub(crate) engagement_identifier: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) sender_aws_account_id: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListEngagementInvitationsInputBuilder {
    /// <p>Specifies the catalog from which to list the engagement invitations. Use <code>AWS</code> for production invitations or <code>Sandbox</code> for testing environments.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog from which to list the engagement invitations. Use <code>AWS</code> for production invitations or <code>Sandbox</code> for testing environments.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog from which to list the engagement invitations. Use <code>AWS</code> for production invitations or <code>Sandbox</code> for testing environments.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>Specifies the maximum number of engagement invitations to return in the response. If more results are available, a pagination token will be provided.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum number of engagement invitations to return in the response. If more results are available, a pagination token will be provided.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specifies the maximum number of engagement invitations to return in the response. If more results are available, a pagination token will be provided.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A pagination token used to retrieve additional pages of results when the response to a previous request was truncated. Pass this token to continue listing invitations from where the previous call left off.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token used to retrieve additional pages of results when the response to a previous request was truncated. Pass this token to continue listing invitations from where the previous call left off.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token used to retrieve additional pages of results when the response to a previous request was truncated. Pass this token to continue listing invitations from where the previous call left off.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specifies the sorting options for listing engagement invitations. Invitations can be sorted by fields such as <code>InvitationDate</code> or <code>Status</code> to help partners view results in their preferred order.</p>
    pub fn sort(mut self, input: crate::types::OpportunityEngagementInvitationSort) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the sorting options for listing engagement invitations. Invitations can be sorted by fields such as <code>InvitationDate</code> or <code>Status</code> to help partners view results in their preferred order.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::OpportunityEngagementInvitationSort>) -> Self {
        self.sort = input;
        self
    }
    /// <p>Specifies the sorting options for listing engagement invitations. Invitations can be sorted by fields such as <code>InvitationDate</code> or <code>Status</code> to help partners view results in their preferred order.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::OpportunityEngagementInvitationSort> {
        &self.sort
    }
    /// Appends an item to `payload_type`.
    ///
    /// To override the contents of this collection use [`set_payload_type`](Self::set_payload_type).
    ///
    /// <p>Defines the type of payload associated with the engagement invitations to be listed. The attributes in this payload help decide on acceptance or rejection of the invitation.</p>
    pub fn payload_type(mut self, input: crate::types::EngagementInvitationPayloadType) -> Self {
        let mut v = self.payload_type.unwrap_or_default();
        v.push(input);
        self.payload_type = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines the type of payload associated with the engagement invitations to be listed. The attributes in this payload help decide on acceptance or rejection of the invitation.</p>
    pub fn set_payload_type(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EngagementInvitationPayloadType>>) -> Self {
        self.payload_type = input;
        self
    }
    /// <p>Defines the type of payload associated with the engagement invitations to be listed. The attributes in this payload help decide on acceptance or rejection of the invitation.</p>
    pub fn get_payload_type(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EngagementInvitationPayloadType>> {
        &self.payload_type
    }
    /// <p>Specifies the type of participant for which to list engagement invitations. Identifies the role of the participant.</p>
    /// This field is required.
    pub fn participant_type(mut self, input: crate::types::ParticipantType) -> Self {
        self.participant_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of participant for which to list engagement invitations. Identifies the role of the participant.</p>
    pub fn set_participant_type(mut self, input: ::std::option::Option<crate::types::ParticipantType>) -> Self {
        self.participant_type = input;
        self
    }
    /// <p>Specifies the type of participant for which to list engagement invitations. Identifies the role of the participant.</p>
    pub fn get_participant_type(&self) -> &::std::option::Option<crate::types::ParticipantType> {
        &self.participant_type
    }
    /// Appends an item to `status`.
    ///
    /// To override the contents of this collection use [`set_status`](Self::set_status).
    ///
    /// <p>Status values to filter the invitations.</p>
    pub fn status(mut self, input: crate::types::InvitationStatus) -> Self {
        let mut v = self.status.unwrap_or_default();
        v.push(input);
        self.status = ::std::option::Option::Some(v);
        self
    }
    /// <p>Status values to filter the invitations.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InvitationStatus>>) -> Self {
        self.status = input;
        self
    }
    /// <p>Status values to filter the invitations.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InvitationStatus>> {
        &self.status
    }
    /// Appends an item to `engagement_identifier`.
    ///
    /// To override the contents of this collection use [`set_engagement_identifier`](Self::set_engagement_identifier).
    ///
    /// <p>Retrieves a list of engagement invitation summaries based on specified filters. The ListEngagementInvitations operation allows you to view all invitations that you have sent or received. You must specify the ParticipantType to filter invitations where you are either the SENDER or the RECEIVER. Invitations will automatically expire if not accepted within 15 days.</p>
    pub fn engagement_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.engagement_identifier.unwrap_or_default();
        v.push(input.into());
        self.engagement_identifier = ::std::option::Option::Some(v);
        self
    }
    /// <p>Retrieves a list of engagement invitation summaries based on specified filters. The ListEngagementInvitations operation allows you to view all invitations that you have sent or received. You must specify the ParticipantType to filter invitations where you are either the SENDER or the RECEIVER. Invitations will automatically expire if not accepted within 15 days.</p>
    pub fn set_engagement_identifier(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.engagement_identifier = input;
        self
    }
    /// <p>Retrieves a list of engagement invitation summaries based on specified filters. The ListEngagementInvitations operation allows you to view all invitations that you have sent or received. You must specify the ParticipantType to filter invitations where you are either the SENDER or the RECEIVER. Invitations will automatically expire if not accepted within 15 days.</p>
    pub fn get_engagement_identifier(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.engagement_identifier
    }
    /// Appends an item to `sender_aws_account_id`.
    ///
    /// To override the contents of this collection use [`set_sender_aws_account_id`](Self::set_sender_aws_account_id).
    ///
    /// <p>List of sender AWS account IDs to filter the invitations.</p>
    pub fn sender_aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.sender_aws_account_id.unwrap_or_default();
        v.push(input.into());
        self.sender_aws_account_id = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of sender AWS account IDs to filter the invitations.</p>
    pub fn set_sender_aws_account_id(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.sender_aws_account_id = input;
        self
    }
    /// <p>List of sender AWS account IDs to filter the invitations.</p>
    pub fn get_sender_aws_account_id(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.sender_aws_account_id
    }
    /// Consumes the builder and constructs a [`ListEngagementInvitationsInput`](crate::operation::list_engagement_invitations::ListEngagementInvitationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_engagement_invitations::ListEngagementInvitationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_engagement_invitations::ListEngagementInvitationsInput {
            catalog: self.catalog,
            max_results: self.max_results,
            next_token: self.next_token,
            sort: self.sort,
            payload_type: self.payload_type,
            participant_type: self.participant_type,
            status: self.status,
            engagement_identifier: self.engagement_identifier,
            sender_aws_account_id: self.sender_aws_account_id,
        })
    }
}
