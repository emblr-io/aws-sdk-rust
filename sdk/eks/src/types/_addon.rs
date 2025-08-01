// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Amazon EKS add-on. For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html">Amazon EKS add-ons</a> in the <i>Amazon EKS User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Addon {
    /// <p>The name of the add-on.</p>
    pub addon_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of your cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the add-on.</p>
    pub status: ::std::option::Option<crate::types::AddonStatus>,
    /// <p>The version of the add-on.</p>
    pub addon_version: ::std::option::Option<::std::string::String>,
    /// <p>An object that represents the health of the add-on.</p>
    pub health: ::std::option::Option<crate::types::AddonHealth>,
    /// <p>The Amazon Resource Name (ARN) of the add-on.</p>
    pub addon_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Unix epoch timestamp at object creation.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Unix epoch timestamp for the last modification to the object.</p>
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that's bound to the Kubernetes <code>ServiceAccount</code> object that the add-on uses.</p>
    pub service_account_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The publisher of the add-on.</p>
    pub publisher: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the add-on.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.</p>
    pub marketplace_information: ::std::option::Option<crate::types::MarketplaceInformation>,
    /// <p>The configuration values that you provided.</p>
    pub configuration_values: ::std::option::Option<::std::string::String>,
    /// <p>An array of EKS Pod Identity associations owned by the add-on. Each association maps a role to a service account in a namespace in the cluster.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/add-ons-iam.html">Attach an IAM Role to an Amazon EKS add-on using EKS Pod Identity</a> in the <i>Amazon EKS User Guide</i>.</p>
    pub pod_identity_associations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Addon {
    /// <p>The name of the add-on.</p>
    pub fn addon_name(&self) -> ::std::option::Option<&str> {
        self.addon_name.as_deref()
    }
    /// <p>The name of your cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The status of the add-on.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AddonStatus> {
        self.status.as_ref()
    }
    /// <p>The version of the add-on.</p>
    pub fn addon_version(&self) -> ::std::option::Option<&str> {
        self.addon_version.as_deref()
    }
    /// <p>An object that represents the health of the add-on.</p>
    pub fn health(&self) -> ::std::option::Option<&crate::types::AddonHealth> {
        self.health.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the add-on.</p>
    pub fn addon_arn(&self) -> ::std::option::Option<&str> {
        self.addon_arn.as_deref()
    }
    /// <p>The Unix epoch timestamp at object creation.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Unix epoch timestamp for the last modification to the object.</p>
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that's bound to the Kubernetes <code>ServiceAccount</code> object that the add-on uses.</p>
    pub fn service_account_role_arn(&self) -> ::std::option::Option<&str> {
        self.service_account_role_arn.as_deref()
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The publisher of the add-on.</p>
    pub fn publisher(&self) -> ::std::option::Option<&str> {
        self.publisher.as_deref()
    }
    /// <p>The owner of the add-on.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.</p>
    pub fn marketplace_information(&self) -> ::std::option::Option<&crate::types::MarketplaceInformation> {
        self.marketplace_information.as_ref()
    }
    /// <p>The configuration values that you provided.</p>
    pub fn configuration_values(&self) -> ::std::option::Option<&str> {
        self.configuration_values.as_deref()
    }
    /// <p>An array of EKS Pod Identity associations owned by the add-on. Each association maps a role to a service account in a namespace in the cluster.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/add-ons-iam.html">Attach an IAM Role to an Amazon EKS add-on using EKS Pod Identity</a> in the <i>Amazon EKS User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pod_identity_associations.is_none()`.
    pub fn pod_identity_associations(&self) -> &[::std::string::String] {
        self.pod_identity_associations.as_deref().unwrap_or_default()
    }
}
impl Addon {
    /// Creates a new builder-style object to manufacture [`Addon`](crate::types::Addon).
    pub fn builder() -> crate::types::builders::AddonBuilder {
        crate::types::builders::AddonBuilder::default()
    }
}

/// A builder for [`Addon`](crate::types::Addon).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddonBuilder {
    pub(crate) addon_name: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::AddonStatus>,
    pub(crate) addon_version: ::std::option::Option<::std::string::String>,
    pub(crate) health: ::std::option::Option<crate::types::AddonHealth>,
    pub(crate) addon_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) service_account_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) publisher: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) marketplace_information: ::std::option::Option<crate::types::MarketplaceInformation>,
    pub(crate) configuration_values: ::std::option::Option<::std::string::String>,
    pub(crate) pod_identity_associations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AddonBuilder {
    /// <p>The name of the add-on.</p>
    pub fn addon_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the add-on.</p>
    pub fn set_addon_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_name = input;
        self
    }
    /// <p>The name of the add-on.</p>
    pub fn get_addon_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_name
    }
    /// <p>The name of your cluster.</p>
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>The status of the add-on.</p>
    pub fn status(mut self, input: crate::types::AddonStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the add-on.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AddonStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the add-on.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AddonStatus> {
        &self.status
    }
    /// <p>The version of the add-on.</p>
    pub fn addon_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the add-on.</p>
    pub fn set_addon_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_version = input;
        self
    }
    /// <p>The version of the add-on.</p>
    pub fn get_addon_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_version
    }
    /// <p>An object that represents the health of the add-on.</p>
    pub fn health(mut self, input: crate::types::AddonHealth) -> Self {
        self.health = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that represents the health of the add-on.</p>
    pub fn set_health(mut self, input: ::std::option::Option<crate::types::AddonHealth>) -> Self {
        self.health = input;
        self
    }
    /// <p>An object that represents the health of the add-on.</p>
    pub fn get_health(&self) -> &::std::option::Option<crate::types::AddonHealth> {
        &self.health
    }
    /// <p>The Amazon Resource Name (ARN) of the add-on.</p>
    pub fn addon_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the add-on.</p>
    pub fn set_addon_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the add-on.</p>
    pub fn get_addon_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_arn
    }
    /// <p>The Unix epoch timestamp at object creation.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix epoch timestamp at object creation.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix epoch timestamp at object creation.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Unix epoch timestamp for the last modification to the object.</p>
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix epoch timestamp for the last modification to the object.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>The Unix epoch timestamp for the last modification to the object.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that's bound to the Kubernetes <code>ServiceAccount</code> object that the add-on uses.</p>
    pub fn service_account_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_account_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that's bound to the Kubernetes <code>ServiceAccount</code> object that the add-on uses.</p>
    pub fn set_service_account_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_account_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that's bound to the Kubernetes <code>ServiceAccount</code> object that the add-on uses.</p>
    pub fn get_service_account_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_account_role_arn
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The publisher of the add-on.</p>
    pub fn publisher(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.publisher = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The publisher of the add-on.</p>
    pub fn set_publisher(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.publisher = input;
        self
    }
    /// <p>The publisher of the add-on.</p>
    pub fn get_publisher(&self) -> &::std::option::Option<::std::string::String> {
        &self.publisher
    }
    /// <p>The owner of the add-on.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the add-on.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the add-on.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.</p>
    pub fn marketplace_information(mut self, input: crate::types::MarketplaceInformation) -> Self {
        self.marketplace_information = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.</p>
    pub fn set_marketplace_information(mut self, input: ::std::option::Option<crate::types::MarketplaceInformation>) -> Self {
        self.marketplace_information = input;
        self
    }
    /// <p>Information about an Amazon EKS add-on from the Amazon Web Services Marketplace.</p>
    pub fn get_marketplace_information(&self) -> &::std::option::Option<crate::types::MarketplaceInformation> {
        &self.marketplace_information
    }
    /// <p>The configuration values that you provided.</p>
    pub fn configuration_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_values = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration values that you provided.</p>
    pub fn set_configuration_values(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_values = input;
        self
    }
    /// <p>The configuration values that you provided.</p>
    pub fn get_configuration_values(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_values
    }
    /// Appends an item to `pod_identity_associations`.
    ///
    /// To override the contents of this collection use [`set_pod_identity_associations`](Self::set_pod_identity_associations).
    ///
    /// <p>An array of EKS Pod Identity associations owned by the add-on. Each association maps a role to a service account in a namespace in the cluster.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/add-ons-iam.html">Attach an IAM Role to an Amazon EKS add-on using EKS Pod Identity</a> in the <i>Amazon EKS User Guide</i>.</p>
    pub fn pod_identity_associations(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.pod_identity_associations.unwrap_or_default();
        v.push(input.into());
        self.pod_identity_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of EKS Pod Identity associations owned by the add-on. Each association maps a role to a service account in a namespace in the cluster.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/add-ons-iam.html">Attach an IAM Role to an Amazon EKS add-on using EKS Pod Identity</a> in the <i>Amazon EKS User Guide</i>.</p>
    pub fn set_pod_identity_associations(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.pod_identity_associations = input;
        self
    }
    /// <p>An array of EKS Pod Identity associations owned by the add-on. Each association maps a role to a service account in a namespace in the cluster.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/add-ons-iam.html">Attach an IAM Role to an Amazon EKS add-on using EKS Pod Identity</a> in the <i>Amazon EKS User Guide</i>.</p>
    pub fn get_pod_identity_associations(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.pod_identity_associations
    }
    /// Consumes the builder and constructs a [`Addon`](crate::types::Addon).
    pub fn build(self) -> crate::types::Addon {
        crate::types::Addon {
            addon_name: self.addon_name,
            cluster_name: self.cluster_name,
            status: self.status,
            addon_version: self.addon_version,
            health: self.health,
            addon_arn: self.addon_arn,
            created_at: self.created_at,
            modified_at: self.modified_at,
            service_account_role_arn: self.service_account_role_arn,
            tags: self.tags,
            publisher: self.publisher,
            owner: self.owner,
            marketplace_information: self.marketplace_information,
            configuration_values: self.configuration_values,
            pod_identity_associations: self.pod_identity_associations,
        }
    }
}
