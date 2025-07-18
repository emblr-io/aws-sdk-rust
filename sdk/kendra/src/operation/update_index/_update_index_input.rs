// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateIndexInput {
    /// <p>The identifier of the index you want to update.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A new name for the index.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An Identity and Access Management (IAM) role that gives Amazon Kendra permission to access Amazon CloudWatch logs and metrics.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A new description for the index.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The document metadata configuration you want to update for the index. Document metadata are fields or attributes associated with your documents. For example, the company department name associated with each document.</p>
    pub document_metadata_configuration_updates: ::std::option::Option<::std::vec::Vec<crate::types::DocumentMetadataConfiguration>>,
    /// <p>Sets the number of additional document storage and query capacity units that should be used by the index. You can change the capacity of the index up to 5 times per day, or make 5 API calls.</p>
    /// <p>If you are using extra storage units, you can't reduce the storage capacity below what is required to meet the storage needs for your index.</p>
    pub capacity_units: ::std::option::Option<crate::types::CapacityUnitsConfiguration>,
    /// <p>The user token configuration.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>UserTokenConfigurations</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub user_token_configurations: ::std::option::Option<::std::vec::Vec<crate::types::UserTokenConfiguration>>,
    /// <p>The user context policy.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, you can only use <code>ATTRIBUTE_FILTER</code> to filter search results by user context. If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>USER_TOKEN</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub user_context_policy: ::std::option::Option<crate::types::UserContextPolicy>,
    /// <p>Gets users and groups from IAM Identity Center identity source. To configure this, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_UserGroupResolutionConfiguration.html">UserGroupResolutionConfiguration</a>. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, <code>UserGroupResolutionConfiguration</code> isn't supported.</p>
    /// </important>
    pub user_group_resolution_configuration: ::std::option::Option<crate::types::UserGroupResolutionConfiguration>,
}
impl UpdateIndexInput {
    /// <p>The identifier of the index you want to update.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A new name for the index.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An Identity and Access Management (IAM) role that gives Amazon Kendra permission to access Amazon CloudWatch logs and metrics.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A new description for the index.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The document metadata configuration you want to update for the index. Document metadata are fields or attributes associated with your documents. For example, the company department name associated with each document.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.document_metadata_configuration_updates.is_none()`.
    pub fn document_metadata_configuration_updates(&self) -> &[crate::types::DocumentMetadataConfiguration] {
        self.document_metadata_configuration_updates.as_deref().unwrap_or_default()
    }
    /// <p>Sets the number of additional document storage and query capacity units that should be used by the index. You can change the capacity of the index up to 5 times per day, or make 5 API calls.</p>
    /// <p>If you are using extra storage units, you can't reduce the storage capacity below what is required to meet the storage needs for your index.</p>
    pub fn capacity_units(&self) -> ::std::option::Option<&crate::types::CapacityUnitsConfiguration> {
        self.capacity_units.as_ref()
    }
    /// <p>The user token configuration.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>UserTokenConfigurations</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_token_configurations.is_none()`.
    pub fn user_token_configurations(&self) -> &[crate::types::UserTokenConfiguration] {
        self.user_token_configurations.as_deref().unwrap_or_default()
    }
    /// <p>The user context policy.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, you can only use <code>ATTRIBUTE_FILTER</code> to filter search results by user context. If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>USER_TOKEN</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn user_context_policy(&self) -> ::std::option::Option<&crate::types::UserContextPolicy> {
        self.user_context_policy.as_ref()
    }
    /// <p>Gets users and groups from IAM Identity Center identity source. To configure this, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_UserGroupResolutionConfiguration.html">UserGroupResolutionConfiguration</a>. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, <code>UserGroupResolutionConfiguration</code> isn't supported.</p>
    /// </important>
    pub fn user_group_resolution_configuration(&self) -> ::std::option::Option<&crate::types::UserGroupResolutionConfiguration> {
        self.user_group_resolution_configuration.as_ref()
    }
}
impl UpdateIndexInput {
    /// Creates a new builder-style object to manufacture [`UpdateIndexInput`](crate::operation::update_index::UpdateIndexInput).
    pub fn builder() -> crate::operation::update_index::builders::UpdateIndexInputBuilder {
        crate::operation::update_index::builders::UpdateIndexInputBuilder::default()
    }
}

/// A builder for [`UpdateIndexInput`](crate::operation::update_index::UpdateIndexInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateIndexInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) document_metadata_configuration_updates: ::std::option::Option<::std::vec::Vec<crate::types::DocumentMetadataConfiguration>>,
    pub(crate) capacity_units: ::std::option::Option<crate::types::CapacityUnitsConfiguration>,
    pub(crate) user_token_configurations: ::std::option::Option<::std::vec::Vec<crate::types::UserTokenConfiguration>>,
    pub(crate) user_context_policy: ::std::option::Option<crate::types::UserContextPolicy>,
    pub(crate) user_group_resolution_configuration: ::std::option::Option<crate::types::UserGroupResolutionConfiguration>,
}
impl UpdateIndexInputBuilder {
    /// <p>The identifier of the index you want to update.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the index you want to update.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the index you want to update.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A new name for the index.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A new name for the index.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A new name for the index.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An Identity and Access Management (IAM) role that gives Amazon Kendra permission to access Amazon CloudWatch logs and metrics.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Identity and Access Management (IAM) role that gives Amazon Kendra permission to access Amazon CloudWatch logs and metrics.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>An Identity and Access Management (IAM) role that gives Amazon Kendra permission to access Amazon CloudWatch logs and metrics.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>A new description for the index.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A new description for the index.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A new description for the index.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `document_metadata_configuration_updates`.
    ///
    /// To override the contents of this collection use [`set_document_metadata_configuration_updates`](Self::set_document_metadata_configuration_updates).
    ///
    /// <p>The document metadata configuration you want to update for the index. Document metadata are fields or attributes associated with your documents. For example, the company department name associated with each document.</p>
    pub fn document_metadata_configuration_updates(mut self, input: crate::types::DocumentMetadataConfiguration) -> Self {
        let mut v = self.document_metadata_configuration_updates.unwrap_or_default();
        v.push(input);
        self.document_metadata_configuration_updates = ::std::option::Option::Some(v);
        self
    }
    /// <p>The document metadata configuration you want to update for the index. Document metadata are fields or attributes associated with your documents. For example, the company department name associated with each document.</p>
    pub fn set_document_metadata_configuration_updates(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentMetadataConfiguration>>,
    ) -> Self {
        self.document_metadata_configuration_updates = input;
        self
    }
    /// <p>The document metadata configuration you want to update for the index. Document metadata are fields or attributes associated with your documents. For example, the company department name associated with each document.</p>
    pub fn get_document_metadata_configuration_updates(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentMetadataConfiguration>> {
        &self.document_metadata_configuration_updates
    }
    /// <p>Sets the number of additional document storage and query capacity units that should be used by the index. You can change the capacity of the index up to 5 times per day, or make 5 API calls.</p>
    /// <p>If you are using extra storage units, you can't reduce the storage capacity below what is required to meet the storage needs for your index.</p>
    pub fn capacity_units(mut self, input: crate::types::CapacityUnitsConfiguration) -> Self {
        self.capacity_units = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the number of additional document storage and query capacity units that should be used by the index. You can change the capacity of the index up to 5 times per day, or make 5 API calls.</p>
    /// <p>If you are using extra storage units, you can't reduce the storage capacity below what is required to meet the storage needs for your index.</p>
    pub fn set_capacity_units(mut self, input: ::std::option::Option<crate::types::CapacityUnitsConfiguration>) -> Self {
        self.capacity_units = input;
        self
    }
    /// <p>Sets the number of additional document storage and query capacity units that should be used by the index. You can change the capacity of the index up to 5 times per day, or make 5 API calls.</p>
    /// <p>If you are using extra storage units, you can't reduce the storage capacity below what is required to meet the storage needs for your index.</p>
    pub fn get_capacity_units(&self) -> &::std::option::Option<crate::types::CapacityUnitsConfiguration> {
        &self.capacity_units
    }
    /// Appends an item to `user_token_configurations`.
    ///
    /// To override the contents of this collection use [`set_user_token_configurations`](Self::set_user_token_configurations).
    ///
    /// <p>The user token configuration.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>UserTokenConfigurations</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn user_token_configurations(mut self, input: crate::types::UserTokenConfiguration) -> Self {
        let mut v = self.user_token_configurations.unwrap_or_default();
        v.push(input);
        self.user_token_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The user token configuration.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>UserTokenConfigurations</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn set_user_token_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserTokenConfiguration>>) -> Self {
        self.user_token_configurations = input;
        self
    }
    /// <p>The user token configuration.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>UserTokenConfigurations</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn get_user_token_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserTokenConfiguration>> {
        &self.user_token_configurations
    }
    /// <p>The user context policy.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, you can only use <code>ATTRIBUTE_FILTER</code> to filter search results by user context. If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>USER_TOKEN</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn user_context_policy(mut self, input: crate::types::UserContextPolicy) -> Self {
        self.user_context_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user context policy.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, you can only use <code>ATTRIBUTE_FILTER</code> to filter search results by user context. If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>USER_TOKEN</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn set_user_context_policy(mut self, input: ::std::option::Option<crate::types::UserContextPolicy>) -> Self {
        self.user_context_policy = input;
        self
    }
    /// <p>The user context policy.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, you can only use <code>ATTRIBUTE_FILTER</code> to filter search results by user context. If you're using an Amazon Kendra Gen AI Enterprise Edition index and you try to use <code>USER_TOKEN</code> to configure user context policy, Amazon Kendra returns a <code>ValidationException</code> error.</p>
    /// </important>
    pub fn get_user_context_policy(&self) -> &::std::option::Option<crate::types::UserContextPolicy> {
        &self.user_context_policy
    }
    /// <p>Gets users and groups from IAM Identity Center identity source. To configure this, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_UserGroupResolutionConfiguration.html">UserGroupResolutionConfiguration</a>. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, <code>UserGroupResolutionConfiguration</code> isn't supported.</p>
    /// </important>
    pub fn user_group_resolution_configuration(mut self, input: crate::types::UserGroupResolutionConfiguration) -> Self {
        self.user_group_resolution_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Gets users and groups from IAM Identity Center identity source. To configure this, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_UserGroupResolutionConfiguration.html">UserGroupResolutionConfiguration</a>. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, <code>UserGroupResolutionConfiguration</code> isn't supported.</p>
    /// </important>
    pub fn set_user_group_resolution_configuration(mut self, input: ::std::option::Option<crate::types::UserGroupResolutionConfiguration>) -> Self {
        self.user_group_resolution_configuration = input;
        self
    }
    /// <p>Gets users and groups from IAM Identity Center identity source. To configure this, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_UserGroupResolutionConfiguration.html">UserGroupResolutionConfiguration</a>. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p><important>
    /// <p>If you're using an Amazon Kendra Gen AI Enterprise Edition index, <code>UserGroupResolutionConfiguration</code> isn't supported.</p>
    /// </important>
    pub fn get_user_group_resolution_configuration(&self) -> &::std::option::Option<crate::types::UserGroupResolutionConfiguration> {
        &self.user_group_resolution_configuration
    }
    /// Consumes the builder and constructs a [`UpdateIndexInput`](crate::operation::update_index::UpdateIndexInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::update_index::UpdateIndexInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_index::UpdateIndexInput {
            id: self.id,
            name: self.name,
            role_arn: self.role_arn,
            description: self.description,
            document_metadata_configuration_updates: self.document_metadata_configuration_updates,
            capacity_units: self.capacity_units,
            user_token_configurations: self.user_token_configurations,
            user_context_policy: self.user_context_policy,
            user_group_resolution_configuration: self.user_group_resolution_configuration,
        })
    }
}
