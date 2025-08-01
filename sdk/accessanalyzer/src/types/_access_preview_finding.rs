// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An access preview finding generated by the access preview.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessPreviewFinding {
    /// <p>The ID of the access preview finding. This ID uniquely identifies the element in the list of access preview findings and is not related to the finding ID in Access Analyzer.</p>
    pub id: ::std::string::String,
    /// <p>The existing ID of the finding in IAM Access Analyzer, provided only for existing findings.</p>
    pub existing_finding_id: ::std::option::Option<::std::string::String>,
    /// <p>The existing status of the finding, provided only for existing findings.</p>
    pub existing_finding_status: ::std::option::Option<crate::types::FindingStatus>,
    /// <p>The external principal that has access to a resource within the zone of trust.</p>
    pub principal: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The action in the analyzed policy statement that an external principal has permission to perform.</p>
    pub action: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The condition in the analyzed policy statement that resulted in a finding.</p>
    pub condition: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The resource that an external principal has access to. This is the resource associated with the access preview.</p>
    pub resource: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the policy that generated the finding allows public access to the resource.</p>
    pub is_public: ::std::option::Option<bool>,
    /// <p>The type of the resource that can be accessed in the finding.</p>
    pub resource_type: crate::types::ResourceType,
    /// <p>The time at which the access preview finding was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>Provides context on how the access preview finding compares to existing access identified in IAM Access Analyzer.</p>
    /// <ul>
    /// <li>
    /// <p><code>New</code> - The finding is for newly-introduced access.</p></li>
    /// <li>
    /// <p><code>Unchanged</code> - The preview finding is an existing finding that would remain unchanged.</p></li>
    /// <li>
    /// <p><code>Changed</code> - The preview finding is an existing finding with a change in status.</p></li>
    /// </ul>
    /// <p>For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub change_type: crate::types::FindingChangeType,
    /// <p>The preview status of the finding. This is what the status of the finding would be after permissions deployment. For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub status: crate::types::FindingStatus,
    /// <p>The Amazon Web Services account ID that owns the resource. For most Amazon Web Services resources, the owning account is the account in which the resource was created.</p>
    pub resource_owner_account: ::std::string::String,
    /// <p>An error.</p>
    pub error: ::std::option::Option<::std::string::String>,
    /// <p>The sources of the finding. This indicates how the access that generated the finding is granted. It is populated for Amazon S3 bucket findings.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::FindingSource>>,
    /// <p>The type of restriction applied to the finding by the resource owner with an Organizations resource control policy (RCP).</p>
    pub resource_control_policy_restriction: ::std::option::Option<crate::types::ResourceControlPolicyRestriction>,
}
impl AccessPreviewFinding {
    /// <p>The ID of the access preview finding. This ID uniquely identifies the element in the list of access preview findings and is not related to the finding ID in Access Analyzer.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The existing ID of the finding in IAM Access Analyzer, provided only for existing findings.</p>
    pub fn existing_finding_id(&self) -> ::std::option::Option<&str> {
        self.existing_finding_id.as_deref()
    }
    /// <p>The existing status of the finding, provided only for existing findings.</p>
    pub fn existing_finding_status(&self) -> ::std::option::Option<&crate::types::FindingStatus> {
        self.existing_finding_status.as_ref()
    }
    /// <p>The external principal that has access to a resource within the zone of trust.</p>
    pub fn principal(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.principal.as_ref()
    }
    /// <p>The action in the analyzed policy statement that an external principal has permission to perform.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.action.is_none()`.
    pub fn action(&self) -> &[::std::string::String] {
        self.action.as_deref().unwrap_or_default()
    }
    /// <p>The condition in the analyzed policy statement that resulted in a finding.</p>
    pub fn condition(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.condition.as_ref()
    }
    /// <p>The resource that an external principal has access to. This is the resource associated with the access preview.</p>
    pub fn resource(&self) -> ::std::option::Option<&str> {
        self.resource.as_deref()
    }
    /// <p>Indicates whether the policy that generated the finding allows public access to the resource.</p>
    pub fn is_public(&self) -> ::std::option::Option<bool> {
        self.is_public
    }
    /// <p>The type of the resource that can be accessed in the finding.</p>
    pub fn resource_type(&self) -> &crate::types::ResourceType {
        &self.resource_type
    }
    /// <p>The time at which the access preview finding was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>Provides context on how the access preview finding compares to existing access identified in IAM Access Analyzer.</p>
    /// <ul>
    /// <li>
    /// <p><code>New</code> - The finding is for newly-introduced access.</p></li>
    /// <li>
    /// <p><code>Unchanged</code> - The preview finding is an existing finding that would remain unchanged.</p></li>
    /// <li>
    /// <p><code>Changed</code> - The preview finding is an existing finding with a change in status.</p></li>
    /// </ul>
    /// <p>For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn change_type(&self) -> &crate::types::FindingChangeType {
        &self.change_type
    }
    /// <p>The preview status of the finding. This is what the status of the finding would be after permissions deployment. For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn status(&self) -> &crate::types::FindingStatus {
        &self.status
    }
    /// <p>The Amazon Web Services account ID that owns the resource. For most Amazon Web Services resources, the owning account is the account in which the resource was created.</p>
    pub fn resource_owner_account(&self) -> &str {
        use std::ops::Deref;
        self.resource_owner_account.deref()
    }
    /// <p>An error.</p>
    pub fn error(&self) -> ::std::option::Option<&str> {
        self.error.as_deref()
    }
    /// <p>The sources of the finding. This indicates how the access that generated the finding is granted. It is populated for Amazon S3 bucket findings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::FindingSource] {
        self.sources.as_deref().unwrap_or_default()
    }
    /// <p>The type of restriction applied to the finding by the resource owner with an Organizations resource control policy (RCP).</p>
    pub fn resource_control_policy_restriction(&self) -> ::std::option::Option<&crate::types::ResourceControlPolicyRestriction> {
        self.resource_control_policy_restriction.as_ref()
    }
}
impl AccessPreviewFinding {
    /// Creates a new builder-style object to manufacture [`AccessPreviewFinding`](crate::types::AccessPreviewFinding).
    pub fn builder() -> crate::types::builders::AccessPreviewFindingBuilder {
        crate::types::builders::AccessPreviewFindingBuilder::default()
    }
}

/// A builder for [`AccessPreviewFinding`](crate::types::AccessPreviewFinding).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessPreviewFindingBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) existing_finding_id: ::std::option::Option<::std::string::String>,
    pub(crate) existing_finding_status: ::std::option::Option<crate::types::FindingStatus>,
    pub(crate) principal: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) action: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) condition: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) resource: ::std::option::Option<::std::string::String>,
    pub(crate) is_public: ::std::option::Option<bool>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) change_type: ::std::option::Option<crate::types::FindingChangeType>,
    pub(crate) status: ::std::option::Option<crate::types::FindingStatus>,
    pub(crate) resource_owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) error: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::FindingSource>>,
    pub(crate) resource_control_policy_restriction: ::std::option::Option<crate::types::ResourceControlPolicyRestriction>,
}
impl AccessPreviewFindingBuilder {
    /// <p>The ID of the access preview finding. This ID uniquely identifies the element in the list of access preview findings and is not related to the finding ID in Access Analyzer.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the access preview finding. This ID uniquely identifies the element in the list of access preview findings and is not related to the finding ID in Access Analyzer.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the access preview finding. This ID uniquely identifies the element in the list of access preview findings and is not related to the finding ID in Access Analyzer.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The existing ID of the finding in IAM Access Analyzer, provided only for existing findings.</p>
    pub fn existing_finding_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.existing_finding_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The existing ID of the finding in IAM Access Analyzer, provided only for existing findings.</p>
    pub fn set_existing_finding_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.existing_finding_id = input;
        self
    }
    /// <p>The existing ID of the finding in IAM Access Analyzer, provided only for existing findings.</p>
    pub fn get_existing_finding_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.existing_finding_id
    }
    /// <p>The existing status of the finding, provided only for existing findings.</p>
    pub fn existing_finding_status(mut self, input: crate::types::FindingStatus) -> Self {
        self.existing_finding_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The existing status of the finding, provided only for existing findings.</p>
    pub fn set_existing_finding_status(mut self, input: ::std::option::Option<crate::types::FindingStatus>) -> Self {
        self.existing_finding_status = input;
        self
    }
    /// <p>The existing status of the finding, provided only for existing findings.</p>
    pub fn get_existing_finding_status(&self) -> &::std::option::Option<crate::types::FindingStatus> {
        &self.existing_finding_status
    }
    /// Adds a key-value pair to `principal`.
    ///
    /// To override the contents of this collection use [`set_principal`](Self::set_principal).
    ///
    /// <p>The external principal that has access to a resource within the zone of trust.</p>
    pub fn principal(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.principal.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.principal = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The external principal that has access to a resource within the zone of trust.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The external principal that has access to a resource within the zone of trust.</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.principal
    }
    /// Appends an item to `action`.
    ///
    /// To override the contents of this collection use [`set_action`](Self::set_action).
    ///
    /// <p>The action in the analyzed policy statement that an external principal has permission to perform.</p>
    pub fn action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.action.unwrap_or_default();
        v.push(input.into());
        self.action = ::std::option::Option::Some(v);
        self
    }
    /// <p>The action in the analyzed policy statement that an external principal has permission to perform.</p>
    pub fn set_action(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action in the analyzed policy statement that an external principal has permission to perform.</p>
    pub fn get_action(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.action
    }
    /// Adds a key-value pair to `condition`.
    ///
    /// To override the contents of this collection use [`set_condition`](Self::set_condition).
    ///
    /// <p>The condition in the analyzed policy statement that resulted in a finding.</p>
    pub fn condition(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.condition.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.condition = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The condition in the analyzed policy statement that resulted in a finding.</p>
    pub fn set_condition(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.condition = input;
        self
    }
    /// <p>The condition in the analyzed policy statement that resulted in a finding.</p>
    pub fn get_condition(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.condition
    }
    /// <p>The resource that an external principal has access to. This is the resource associated with the access preview.</p>
    pub fn resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource that an external principal has access to. This is the resource associated with the access preview.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The resource that an external principal has access to. This is the resource associated with the access preview.</p>
    pub fn get_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource
    }
    /// <p>Indicates whether the policy that generated the finding allows public access to the resource.</p>
    pub fn is_public(mut self, input: bool) -> Self {
        self.is_public = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the policy that generated the finding allows public access to the resource.</p>
    pub fn set_is_public(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_public = input;
        self
    }
    /// <p>Indicates whether the policy that generated the finding allows public access to the resource.</p>
    pub fn get_is_public(&self) -> &::std::option::Option<bool> {
        &self.is_public
    }
    /// <p>The type of the resource that can be accessed in the finding.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the resource that can be accessed in the finding.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of the resource that can be accessed in the finding.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// <p>The time at which the access preview finding was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the access preview finding was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time at which the access preview finding was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>Provides context on how the access preview finding compares to existing access identified in IAM Access Analyzer.</p>
    /// <ul>
    /// <li>
    /// <p><code>New</code> - The finding is for newly-introduced access.</p></li>
    /// <li>
    /// <p><code>Unchanged</code> - The preview finding is an existing finding that would remain unchanged.</p></li>
    /// <li>
    /// <p><code>Changed</code> - The preview finding is an existing finding with a change in status.</p></li>
    /// </ul>
    /// <p>For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    /// This field is required.
    pub fn change_type(mut self, input: crate::types::FindingChangeType) -> Self {
        self.change_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides context on how the access preview finding compares to existing access identified in IAM Access Analyzer.</p>
    /// <ul>
    /// <li>
    /// <p><code>New</code> - The finding is for newly-introduced access.</p></li>
    /// <li>
    /// <p><code>Unchanged</code> - The preview finding is an existing finding that would remain unchanged.</p></li>
    /// <li>
    /// <p><code>Changed</code> - The preview finding is an existing finding with a change in status.</p></li>
    /// </ul>
    /// <p>For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn set_change_type(mut self, input: ::std::option::Option<crate::types::FindingChangeType>) -> Self {
        self.change_type = input;
        self
    }
    /// <p>Provides context on how the access preview finding compares to existing access identified in IAM Access Analyzer.</p>
    /// <ul>
    /// <li>
    /// <p><code>New</code> - The finding is for newly-introduced access.</p></li>
    /// <li>
    /// <p><code>Unchanged</code> - The preview finding is an existing finding that would remain unchanged.</p></li>
    /// <li>
    /// <p><code>Changed</code> - The preview finding is an existing finding with a change in status.</p></li>
    /// </ul>
    /// <p>For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn get_change_type(&self) -> &::std::option::Option<crate::types::FindingChangeType> {
        &self.change_type
    }
    /// <p>The preview status of the finding. This is what the status of the finding would be after permissions deployment. For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::FindingStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The preview status of the finding. This is what the status of the finding would be after permissions deployment. For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FindingStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The preview status of the finding. This is what the status of the finding would be after permissions deployment. For example, a <code>Changed</code> finding with preview status <code>Resolved</code> and existing status <code>Active</code> indicates the existing <code>Active</code> finding would become <code>Resolved</code> as a result of the proposed permissions change.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FindingStatus> {
        &self.status
    }
    /// <p>The Amazon Web Services account ID that owns the resource. For most Amazon Web Services resources, the owning account is the account in which the resource was created.</p>
    /// This field is required.
    pub fn resource_owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID that owns the resource. For most Amazon Web Services resources, the owning account is the account in which the resource was created.</p>
    pub fn set_resource_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner_account = input;
        self
    }
    /// <p>The Amazon Web Services account ID that owns the resource. For most Amazon Web Services resources, the owning account is the account in which the resource was created.</p>
    pub fn get_resource_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner_account
    }
    /// <p>An error.</p>
    pub fn error(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An error.</p>
    pub fn set_error(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error = input;
        self
    }
    /// <p>An error.</p>
    pub fn get_error(&self) -> &::std::option::Option<::std::string::String> {
        &self.error
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The sources of the finding. This indicates how the access that generated the finding is granted. It is populated for Amazon S3 bucket findings.</p>
    pub fn sources(mut self, input: crate::types::FindingSource) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sources of the finding. This indicates how the access that generated the finding is granted. It is populated for Amazon S3 bucket findings.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FindingSource>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The sources of the finding. This indicates how the access that generated the finding is granted. It is populated for Amazon S3 bucket findings.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FindingSource>> {
        &self.sources
    }
    /// <p>The type of restriction applied to the finding by the resource owner with an Organizations resource control policy (RCP).</p>
    pub fn resource_control_policy_restriction(mut self, input: crate::types::ResourceControlPolicyRestriction) -> Self {
        self.resource_control_policy_restriction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of restriction applied to the finding by the resource owner with an Organizations resource control policy (RCP).</p>
    pub fn set_resource_control_policy_restriction(mut self, input: ::std::option::Option<crate::types::ResourceControlPolicyRestriction>) -> Self {
        self.resource_control_policy_restriction = input;
        self
    }
    /// <p>The type of restriction applied to the finding by the resource owner with an Organizations resource control policy (RCP).</p>
    pub fn get_resource_control_policy_restriction(&self) -> &::std::option::Option<crate::types::ResourceControlPolicyRestriction> {
        &self.resource_control_policy_restriction
    }
    /// Consumes the builder and constructs a [`AccessPreviewFinding`](crate::types::AccessPreviewFinding).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::AccessPreviewFindingBuilder::id)
    /// - [`resource_type`](crate::types::builders::AccessPreviewFindingBuilder::resource_type)
    /// - [`created_at`](crate::types::builders::AccessPreviewFindingBuilder::created_at)
    /// - [`change_type`](crate::types::builders::AccessPreviewFindingBuilder::change_type)
    /// - [`status`](crate::types::builders::AccessPreviewFindingBuilder::status)
    /// - [`resource_owner_account`](crate::types::builders::AccessPreviewFindingBuilder::resource_owner_account)
    pub fn build(self) -> ::std::result::Result<crate::types::AccessPreviewFinding, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AccessPreviewFinding {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            existing_finding_id: self.existing_finding_id,
            existing_finding_status: self.existing_finding_status,
            principal: self.principal,
            action: self.action,
            condition: self.condition,
            resource: self.resource,
            is_public: self.is_public,
            resource_type: self.resource_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_type",
                    "resource_type was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            change_type: self.change_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "change_type",
                    "change_type was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            resource_owner_account: self.resource_owner_account.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_owner_account",
                    "resource_owner_account was not specified but it is required when building AccessPreviewFinding",
                )
            })?,
            error: self.error,
            sources: self.sources,
            resource_control_policy_restriction: self.resource_control_policy_restriction,
        })
    }
}
