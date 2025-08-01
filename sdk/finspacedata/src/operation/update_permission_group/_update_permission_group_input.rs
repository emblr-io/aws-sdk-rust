// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdatePermissionGroupInput {
    /// <p>The unique identifier for the permission group to update.</p>
    pub permission_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the permission group.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A brief description for the permission group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The permissions that are granted to a specific group for accessing the FinSpace application.</p><important>
    /// <p>When assigning application permissions, be aware that the permission <code>ManageUsersAndGroups</code> allows users to grant themselves or others access to any functionality in their FinSpace environment's application. It should only be granted to trusted users.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>CreateDataset</code> – Group members can create new datasets.</p></li>
    /// <li>
    /// <p><code>ManageClusters</code> – Group members can manage Apache Spark clusters from FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>ManageUsersAndGroups</code> – Group members can manage users and permission groups. This is a privileged permission that allows users to grant themselves or others access to any functionality in the application. It should only be granted to trusted users.</p></li>
    /// <li>
    /// <p><code>ManageAttributeSets</code> – Group members can manage attribute sets.</p></li>
    /// <li>
    /// <p><code>ViewAuditData</code> – Group members can view audit data.</p></li>
    /// <li>
    /// <p><code>AccessNotebooks</code> – Group members will have access to FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>GetTemporaryCredentials</code> – Group members can get temporary API credentials.</p></li>
    /// </ul>
    pub application_permissions: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPermission>>,
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdatePermissionGroupInput {
    /// <p>The unique identifier for the permission group to update.</p>
    pub fn permission_group_id(&self) -> ::std::option::Option<&str> {
        self.permission_group_id.as_deref()
    }
    /// <p>The name of the permission group.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A brief description for the permission group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The permissions that are granted to a specific group for accessing the FinSpace application.</p><important>
    /// <p>When assigning application permissions, be aware that the permission <code>ManageUsersAndGroups</code> allows users to grant themselves or others access to any functionality in their FinSpace environment's application. It should only be granted to trusted users.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>CreateDataset</code> – Group members can create new datasets.</p></li>
    /// <li>
    /// <p><code>ManageClusters</code> – Group members can manage Apache Spark clusters from FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>ManageUsersAndGroups</code> – Group members can manage users and permission groups. This is a privileged permission that allows users to grant themselves or others access to any functionality in the application. It should only be granted to trusted users.</p></li>
    /// <li>
    /// <p><code>ManageAttributeSets</code> – Group members can manage attribute sets.</p></li>
    /// <li>
    /// <p><code>ViewAuditData</code> – Group members can view audit data.</p></li>
    /// <li>
    /// <p><code>AccessNotebooks</code> – Group members will have access to FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>GetTemporaryCredentials</code> – Group members can get temporary API credentials.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.application_permissions.is_none()`.
    pub fn application_permissions(&self) -> &[crate::types::ApplicationPermission] {
        self.application_permissions.as_deref().unwrap_or_default()
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::std::fmt::Debug for UpdatePermissionGroupInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatePermissionGroupInput");
        formatter.field("permission_group_id", &self.permission_group_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("application_permissions", &self.application_permissions);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
impl UpdatePermissionGroupInput {
    /// Creates a new builder-style object to manufacture [`UpdatePermissionGroupInput`](crate::operation::update_permission_group::UpdatePermissionGroupInput).
    pub fn builder() -> crate::operation::update_permission_group::builders::UpdatePermissionGroupInputBuilder {
        crate::operation::update_permission_group::builders::UpdatePermissionGroupInputBuilder::default()
    }
}

/// A builder for [`UpdatePermissionGroupInput`](crate::operation::update_permission_group::UpdatePermissionGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdatePermissionGroupInputBuilder {
    pub(crate) permission_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) application_permissions: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPermission>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdatePermissionGroupInputBuilder {
    /// <p>The unique identifier for the permission group to update.</p>
    /// This field is required.
    pub fn permission_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the permission group to update.</p>
    pub fn set_permission_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_group_id = input;
        self
    }
    /// <p>The unique identifier for the permission group to update.</p>
    pub fn get_permission_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_group_id
    }
    /// <p>The name of the permission group.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the permission group.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the permission group.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A brief description for the permission group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description for the permission group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description for the permission group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `application_permissions`.
    ///
    /// To override the contents of this collection use [`set_application_permissions`](Self::set_application_permissions).
    ///
    /// <p>The permissions that are granted to a specific group for accessing the FinSpace application.</p><important>
    /// <p>When assigning application permissions, be aware that the permission <code>ManageUsersAndGroups</code> allows users to grant themselves or others access to any functionality in their FinSpace environment's application. It should only be granted to trusted users.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>CreateDataset</code> – Group members can create new datasets.</p></li>
    /// <li>
    /// <p><code>ManageClusters</code> – Group members can manage Apache Spark clusters from FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>ManageUsersAndGroups</code> – Group members can manage users and permission groups. This is a privileged permission that allows users to grant themselves or others access to any functionality in the application. It should only be granted to trusted users.</p></li>
    /// <li>
    /// <p><code>ManageAttributeSets</code> – Group members can manage attribute sets.</p></li>
    /// <li>
    /// <p><code>ViewAuditData</code> – Group members can view audit data.</p></li>
    /// <li>
    /// <p><code>AccessNotebooks</code> – Group members will have access to FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>GetTemporaryCredentials</code> – Group members can get temporary API credentials.</p></li>
    /// </ul>
    pub fn application_permissions(mut self, input: crate::types::ApplicationPermission) -> Self {
        let mut v = self.application_permissions.unwrap_or_default();
        v.push(input);
        self.application_permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permissions that are granted to a specific group for accessing the FinSpace application.</p><important>
    /// <p>When assigning application permissions, be aware that the permission <code>ManageUsersAndGroups</code> allows users to grant themselves or others access to any functionality in their FinSpace environment's application. It should only be granted to trusted users.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>CreateDataset</code> – Group members can create new datasets.</p></li>
    /// <li>
    /// <p><code>ManageClusters</code> – Group members can manage Apache Spark clusters from FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>ManageUsersAndGroups</code> – Group members can manage users and permission groups. This is a privileged permission that allows users to grant themselves or others access to any functionality in the application. It should only be granted to trusted users.</p></li>
    /// <li>
    /// <p><code>ManageAttributeSets</code> – Group members can manage attribute sets.</p></li>
    /// <li>
    /// <p><code>ViewAuditData</code> – Group members can view audit data.</p></li>
    /// <li>
    /// <p><code>AccessNotebooks</code> – Group members will have access to FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>GetTemporaryCredentials</code> – Group members can get temporary API credentials.</p></li>
    /// </ul>
    pub fn set_application_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPermission>>) -> Self {
        self.application_permissions = input;
        self
    }
    /// <p>The permissions that are granted to a specific group for accessing the FinSpace application.</p><important>
    /// <p>When assigning application permissions, be aware that the permission <code>ManageUsersAndGroups</code> allows users to grant themselves or others access to any functionality in their FinSpace environment's application. It should only be granted to trusted users.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>CreateDataset</code> – Group members can create new datasets.</p></li>
    /// <li>
    /// <p><code>ManageClusters</code> – Group members can manage Apache Spark clusters from FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>ManageUsersAndGroups</code> – Group members can manage users and permission groups. This is a privileged permission that allows users to grant themselves or others access to any functionality in the application. It should only be granted to trusted users.</p></li>
    /// <li>
    /// <p><code>ManageAttributeSets</code> – Group members can manage attribute sets.</p></li>
    /// <li>
    /// <p><code>ViewAuditData</code> – Group members can view audit data.</p></li>
    /// <li>
    /// <p><code>AccessNotebooks</code> – Group members will have access to FinSpace notebooks.</p></li>
    /// <li>
    /// <p><code>GetTemporaryCredentials</code> – Group members can get temporary API credentials.</p></li>
    /// </ul>
    pub fn get_application_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ApplicationPermission>> {
        &self.application_permissions
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdatePermissionGroupInput`](crate::operation::update_permission_group::UpdatePermissionGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_permission_group::UpdatePermissionGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_permission_group::UpdatePermissionGroupInput {
            permission_group_id: self.permission_group_id,
            name: self.name,
            description: self.description,
            application_permissions: self.application_permissions,
            client_token: self.client_token,
        })
    }
}
impl ::std::fmt::Debug for UpdatePermissionGroupInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatePermissionGroupInputBuilder");
        formatter.field("permission_group_id", &self.permission_group_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("application_permissions", &self.application_permissions);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
