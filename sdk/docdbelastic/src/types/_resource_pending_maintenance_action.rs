// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a pending maintenance action for a resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourcePendingMaintenanceAction {
    /// <p>The Amazon DocumentDB Amazon Resource Name (ARN) of the resource to which the pending maintenance action applies.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Provides information about a pending maintenance action for a resource.</p>
    pub pending_maintenance_action_details: ::std::option::Option<::std::vec::Vec<crate::types::PendingMaintenanceActionDetails>>,
}
impl ResourcePendingMaintenanceAction {
    /// <p>The Amazon DocumentDB Amazon Resource Name (ARN) of the resource to which the pending maintenance action applies.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Provides information about a pending maintenance action for a resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pending_maintenance_action_details.is_none()`.
    pub fn pending_maintenance_action_details(&self) -> &[crate::types::PendingMaintenanceActionDetails] {
        self.pending_maintenance_action_details.as_deref().unwrap_or_default()
    }
}
impl ResourcePendingMaintenanceAction {
    /// Creates a new builder-style object to manufacture [`ResourcePendingMaintenanceAction`](crate::types::ResourcePendingMaintenanceAction).
    pub fn builder() -> crate::types::builders::ResourcePendingMaintenanceActionBuilder {
        crate::types::builders::ResourcePendingMaintenanceActionBuilder::default()
    }
}

/// A builder for [`ResourcePendingMaintenanceAction`](crate::types::ResourcePendingMaintenanceAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourcePendingMaintenanceActionBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) pending_maintenance_action_details: ::std::option::Option<::std::vec::Vec<crate::types::PendingMaintenanceActionDetails>>,
}
impl ResourcePendingMaintenanceActionBuilder {
    /// <p>The Amazon DocumentDB Amazon Resource Name (ARN) of the resource to which the pending maintenance action applies.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon DocumentDB Amazon Resource Name (ARN) of the resource to which the pending maintenance action applies.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon DocumentDB Amazon Resource Name (ARN) of the resource to which the pending maintenance action applies.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Appends an item to `pending_maintenance_action_details`.
    ///
    /// To override the contents of this collection use [`set_pending_maintenance_action_details`](Self::set_pending_maintenance_action_details).
    ///
    /// <p>Provides information about a pending maintenance action for a resource.</p>
    pub fn pending_maintenance_action_details(mut self, input: crate::types::PendingMaintenanceActionDetails) -> Self {
        let mut v = self.pending_maintenance_action_details.unwrap_or_default();
        v.push(input);
        self.pending_maintenance_action_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>Provides information about a pending maintenance action for a resource.</p>
    pub fn set_pending_maintenance_action_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::PendingMaintenanceActionDetails>>,
    ) -> Self {
        self.pending_maintenance_action_details = input;
        self
    }
    /// <p>Provides information about a pending maintenance action for a resource.</p>
    pub fn get_pending_maintenance_action_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PendingMaintenanceActionDetails>> {
        &self.pending_maintenance_action_details
    }
    /// Consumes the builder and constructs a [`ResourcePendingMaintenanceAction`](crate::types::ResourcePendingMaintenanceAction).
    pub fn build(self) -> crate::types::ResourcePendingMaintenanceAction {
        crate::types::ResourcePendingMaintenanceAction {
            resource_arn: self.resource_arn,
            pending_maintenance_action_details: self.pending_maintenance_action_details,
        }
    }
}
