// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateReplicationConfigurationTemplateInput {
    /// <p>Request to configure the Staging Area subnet ID during Replication Settings template creation.</p>
    pub staging_area_subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>Request to associate the default Application Migration Service Security group with the Replication Settings template.</p>
    pub associate_default_security_group: ::std::option::Option<bool>,
    /// <p>Request to configure the Replication Server Security group ID during Replication Settings template creation.</p>
    pub replication_servers_security_groups_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Request to configure the Replication Server instance type during Replication Settings template creation.</p>
    pub replication_server_instance_type: ::std::option::Option<::std::string::String>,
    /// <p>Request to use Dedicated Replication Servers during Replication Settings template creation.</p>
    pub use_dedicated_replication_server: ::std::option::Option<bool>,
    /// <p>Request to configure the default large staging disk EBS volume type during Replication Settings template creation.</p>
    pub default_large_staging_disk_type: ::std::option::Option<crate::types::ReplicationConfigurationDefaultLargeStagingDiskType>,
    /// <p>Request to configure EBS encryption during Replication Settings template creation.</p>
    pub ebs_encryption: ::std::option::Option<crate::types::ReplicationConfigurationEbsEncryption>,
    /// <p>Request to configure an EBS encryption key during Replication Settings template creation.</p>
    pub ebs_encryption_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>Request to configure bandwidth throttling during Replication Settings template creation.</p>
    pub bandwidth_throttling: ::std::option::Option<i64>,
    /// <p>Request to configure data plane routing during Replication Settings template creation.</p>
    pub data_plane_routing: ::std::option::Option<crate::types::ReplicationConfigurationDataPlaneRouting>,
    /// <p>Request to create Public IP during Replication Settings template creation.</p>
    pub create_public_ip: ::std::option::Option<bool>,
    /// <p>Request to configure Staging Area tags during Replication Settings template creation.</p>
    pub staging_area_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Request to use Fips Endpoint during Replication Settings template creation.</p>
    pub use_fips_endpoint: ::std::option::Option<bool>,
    /// <p>Request to configure tags during Replication Settings template creation.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateReplicationConfigurationTemplateInput {
    /// <p>Request to configure the Staging Area subnet ID during Replication Settings template creation.</p>
    pub fn staging_area_subnet_id(&self) -> ::std::option::Option<&str> {
        self.staging_area_subnet_id.as_deref()
    }
    /// <p>Request to associate the default Application Migration Service Security group with the Replication Settings template.</p>
    pub fn associate_default_security_group(&self) -> ::std::option::Option<bool> {
        self.associate_default_security_group
    }
    /// <p>Request to configure the Replication Server Security group ID during Replication Settings template creation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_servers_security_groups_ids.is_none()`.
    pub fn replication_servers_security_groups_ids(&self) -> &[::std::string::String] {
        self.replication_servers_security_groups_ids.as_deref().unwrap_or_default()
    }
    /// <p>Request to configure the Replication Server instance type during Replication Settings template creation.</p>
    pub fn replication_server_instance_type(&self) -> ::std::option::Option<&str> {
        self.replication_server_instance_type.as_deref()
    }
    /// <p>Request to use Dedicated Replication Servers during Replication Settings template creation.</p>
    pub fn use_dedicated_replication_server(&self) -> ::std::option::Option<bool> {
        self.use_dedicated_replication_server
    }
    /// <p>Request to configure the default large staging disk EBS volume type during Replication Settings template creation.</p>
    pub fn default_large_staging_disk_type(&self) -> ::std::option::Option<&crate::types::ReplicationConfigurationDefaultLargeStagingDiskType> {
        self.default_large_staging_disk_type.as_ref()
    }
    /// <p>Request to configure EBS encryption during Replication Settings template creation.</p>
    pub fn ebs_encryption(&self) -> ::std::option::Option<&crate::types::ReplicationConfigurationEbsEncryption> {
        self.ebs_encryption.as_ref()
    }
    /// <p>Request to configure an EBS encryption key during Replication Settings template creation.</p>
    pub fn ebs_encryption_key_arn(&self) -> ::std::option::Option<&str> {
        self.ebs_encryption_key_arn.as_deref()
    }
    /// <p>Request to configure bandwidth throttling during Replication Settings template creation.</p>
    pub fn bandwidth_throttling(&self) -> ::std::option::Option<i64> {
        self.bandwidth_throttling
    }
    /// <p>Request to configure data plane routing during Replication Settings template creation.</p>
    pub fn data_plane_routing(&self) -> ::std::option::Option<&crate::types::ReplicationConfigurationDataPlaneRouting> {
        self.data_plane_routing.as_ref()
    }
    /// <p>Request to create Public IP during Replication Settings template creation.</p>
    pub fn create_public_ip(&self) -> ::std::option::Option<bool> {
        self.create_public_ip
    }
    /// <p>Request to configure Staging Area tags during Replication Settings template creation.</p>
    pub fn staging_area_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.staging_area_tags.as_ref()
    }
    /// <p>Request to use Fips Endpoint during Replication Settings template creation.</p>
    pub fn use_fips_endpoint(&self) -> ::std::option::Option<bool> {
        self.use_fips_endpoint
    }
    /// <p>Request to configure tags during Replication Settings template creation.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for CreateReplicationConfigurationTemplateInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateReplicationConfigurationTemplateInput");
        formatter.field("staging_area_subnet_id", &self.staging_area_subnet_id);
        formatter.field("associate_default_security_group", &self.associate_default_security_group);
        formatter.field("replication_servers_security_groups_ids", &self.replication_servers_security_groups_ids);
        formatter.field("replication_server_instance_type", &self.replication_server_instance_type);
        formatter.field("use_dedicated_replication_server", &self.use_dedicated_replication_server);
        formatter.field("default_large_staging_disk_type", &self.default_large_staging_disk_type);
        formatter.field("ebs_encryption", &self.ebs_encryption);
        formatter.field("ebs_encryption_key_arn", &self.ebs_encryption_key_arn);
        formatter.field("bandwidth_throttling", &self.bandwidth_throttling);
        formatter.field("data_plane_routing", &self.data_plane_routing);
        formatter.field("create_public_ip", &self.create_public_ip);
        formatter.field("staging_area_tags", &"*** Sensitive Data Redacted ***");
        formatter.field("use_fips_endpoint", &self.use_fips_endpoint);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateReplicationConfigurationTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateReplicationConfigurationTemplateInput`](crate::operation::create_replication_configuration_template::CreateReplicationConfigurationTemplateInput).
    pub fn builder() -> crate::operation::create_replication_configuration_template::builders::CreateReplicationConfigurationTemplateInputBuilder {
        crate::operation::create_replication_configuration_template::builders::CreateReplicationConfigurationTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateReplicationConfigurationTemplateInput`](crate::operation::create_replication_configuration_template::CreateReplicationConfigurationTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateReplicationConfigurationTemplateInputBuilder {
    pub(crate) staging_area_subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) associate_default_security_group: ::std::option::Option<bool>,
    pub(crate) replication_servers_security_groups_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) replication_server_instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) use_dedicated_replication_server: ::std::option::Option<bool>,
    pub(crate) default_large_staging_disk_type: ::std::option::Option<crate::types::ReplicationConfigurationDefaultLargeStagingDiskType>,
    pub(crate) ebs_encryption: ::std::option::Option<crate::types::ReplicationConfigurationEbsEncryption>,
    pub(crate) ebs_encryption_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) bandwidth_throttling: ::std::option::Option<i64>,
    pub(crate) data_plane_routing: ::std::option::Option<crate::types::ReplicationConfigurationDataPlaneRouting>,
    pub(crate) create_public_ip: ::std::option::Option<bool>,
    pub(crate) staging_area_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) use_fips_endpoint: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateReplicationConfigurationTemplateInputBuilder {
    /// <p>Request to configure the Staging Area subnet ID during Replication Settings template creation.</p>
    /// This field is required.
    pub fn staging_area_subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.staging_area_subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Request to configure the Staging Area subnet ID during Replication Settings template creation.</p>
    pub fn set_staging_area_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.staging_area_subnet_id = input;
        self
    }
    /// <p>Request to configure the Staging Area subnet ID during Replication Settings template creation.</p>
    pub fn get_staging_area_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.staging_area_subnet_id
    }
    /// <p>Request to associate the default Application Migration Service Security group with the Replication Settings template.</p>
    /// This field is required.
    pub fn associate_default_security_group(mut self, input: bool) -> Self {
        self.associate_default_security_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to associate the default Application Migration Service Security group with the Replication Settings template.</p>
    pub fn set_associate_default_security_group(mut self, input: ::std::option::Option<bool>) -> Self {
        self.associate_default_security_group = input;
        self
    }
    /// <p>Request to associate the default Application Migration Service Security group with the Replication Settings template.</p>
    pub fn get_associate_default_security_group(&self) -> &::std::option::Option<bool> {
        &self.associate_default_security_group
    }
    /// Appends an item to `replication_servers_security_groups_ids`.
    ///
    /// To override the contents of this collection use [`set_replication_servers_security_groups_ids`](Self::set_replication_servers_security_groups_ids).
    ///
    /// <p>Request to configure the Replication Server Security group ID during Replication Settings template creation.</p>
    pub fn replication_servers_security_groups_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.replication_servers_security_groups_ids.unwrap_or_default();
        v.push(input.into());
        self.replication_servers_security_groups_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Request to configure the Replication Server Security group ID during Replication Settings template creation.</p>
    pub fn set_replication_servers_security_groups_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.replication_servers_security_groups_ids = input;
        self
    }
    /// <p>Request to configure the Replication Server Security group ID during Replication Settings template creation.</p>
    pub fn get_replication_servers_security_groups_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.replication_servers_security_groups_ids
    }
    /// <p>Request to configure the Replication Server instance type during Replication Settings template creation.</p>
    /// This field is required.
    pub fn replication_server_instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_server_instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Request to configure the Replication Server instance type during Replication Settings template creation.</p>
    pub fn set_replication_server_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_server_instance_type = input;
        self
    }
    /// <p>Request to configure the Replication Server instance type during Replication Settings template creation.</p>
    pub fn get_replication_server_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_server_instance_type
    }
    /// <p>Request to use Dedicated Replication Servers during Replication Settings template creation.</p>
    /// This field is required.
    pub fn use_dedicated_replication_server(mut self, input: bool) -> Self {
        self.use_dedicated_replication_server = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to use Dedicated Replication Servers during Replication Settings template creation.</p>
    pub fn set_use_dedicated_replication_server(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_dedicated_replication_server = input;
        self
    }
    /// <p>Request to use Dedicated Replication Servers during Replication Settings template creation.</p>
    pub fn get_use_dedicated_replication_server(&self) -> &::std::option::Option<bool> {
        &self.use_dedicated_replication_server
    }
    /// <p>Request to configure the default large staging disk EBS volume type during Replication Settings template creation.</p>
    /// This field is required.
    pub fn default_large_staging_disk_type(mut self, input: crate::types::ReplicationConfigurationDefaultLargeStagingDiskType) -> Self {
        self.default_large_staging_disk_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to configure the default large staging disk EBS volume type during Replication Settings template creation.</p>
    pub fn set_default_large_staging_disk_type(
        mut self,
        input: ::std::option::Option<crate::types::ReplicationConfigurationDefaultLargeStagingDiskType>,
    ) -> Self {
        self.default_large_staging_disk_type = input;
        self
    }
    /// <p>Request to configure the default large staging disk EBS volume type during Replication Settings template creation.</p>
    pub fn get_default_large_staging_disk_type(&self) -> &::std::option::Option<crate::types::ReplicationConfigurationDefaultLargeStagingDiskType> {
        &self.default_large_staging_disk_type
    }
    /// <p>Request to configure EBS encryption during Replication Settings template creation.</p>
    /// This field is required.
    pub fn ebs_encryption(mut self, input: crate::types::ReplicationConfigurationEbsEncryption) -> Self {
        self.ebs_encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to configure EBS encryption during Replication Settings template creation.</p>
    pub fn set_ebs_encryption(mut self, input: ::std::option::Option<crate::types::ReplicationConfigurationEbsEncryption>) -> Self {
        self.ebs_encryption = input;
        self
    }
    /// <p>Request to configure EBS encryption during Replication Settings template creation.</p>
    pub fn get_ebs_encryption(&self) -> &::std::option::Option<crate::types::ReplicationConfigurationEbsEncryption> {
        &self.ebs_encryption
    }
    /// <p>Request to configure an EBS encryption key during Replication Settings template creation.</p>
    pub fn ebs_encryption_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ebs_encryption_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Request to configure an EBS encryption key during Replication Settings template creation.</p>
    pub fn set_ebs_encryption_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ebs_encryption_key_arn = input;
        self
    }
    /// <p>Request to configure an EBS encryption key during Replication Settings template creation.</p>
    pub fn get_ebs_encryption_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ebs_encryption_key_arn
    }
    /// <p>Request to configure bandwidth throttling during Replication Settings template creation.</p>
    /// This field is required.
    pub fn bandwidth_throttling(mut self, input: i64) -> Self {
        self.bandwidth_throttling = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to configure bandwidth throttling during Replication Settings template creation.</p>
    pub fn set_bandwidth_throttling(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bandwidth_throttling = input;
        self
    }
    /// <p>Request to configure bandwidth throttling during Replication Settings template creation.</p>
    pub fn get_bandwidth_throttling(&self) -> &::std::option::Option<i64> {
        &self.bandwidth_throttling
    }
    /// <p>Request to configure data plane routing during Replication Settings template creation.</p>
    /// This field is required.
    pub fn data_plane_routing(mut self, input: crate::types::ReplicationConfigurationDataPlaneRouting) -> Self {
        self.data_plane_routing = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to configure data plane routing during Replication Settings template creation.</p>
    pub fn set_data_plane_routing(mut self, input: ::std::option::Option<crate::types::ReplicationConfigurationDataPlaneRouting>) -> Self {
        self.data_plane_routing = input;
        self
    }
    /// <p>Request to configure data plane routing during Replication Settings template creation.</p>
    pub fn get_data_plane_routing(&self) -> &::std::option::Option<crate::types::ReplicationConfigurationDataPlaneRouting> {
        &self.data_plane_routing
    }
    /// <p>Request to create Public IP during Replication Settings template creation.</p>
    /// This field is required.
    pub fn create_public_ip(mut self, input: bool) -> Self {
        self.create_public_ip = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to create Public IP during Replication Settings template creation.</p>
    pub fn set_create_public_ip(mut self, input: ::std::option::Option<bool>) -> Self {
        self.create_public_ip = input;
        self
    }
    /// <p>Request to create Public IP during Replication Settings template creation.</p>
    pub fn get_create_public_ip(&self) -> &::std::option::Option<bool> {
        &self.create_public_ip
    }
    /// Adds a key-value pair to `staging_area_tags`.
    ///
    /// To override the contents of this collection use [`set_staging_area_tags`](Self::set_staging_area_tags).
    ///
    /// <p>Request to configure Staging Area tags during Replication Settings template creation.</p>
    pub fn staging_area_tags(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.staging_area_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.staging_area_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Request to configure Staging Area tags during Replication Settings template creation.</p>
    pub fn set_staging_area_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.staging_area_tags = input;
        self
    }
    /// <p>Request to configure Staging Area tags during Replication Settings template creation.</p>
    pub fn get_staging_area_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.staging_area_tags
    }
    /// <p>Request to use Fips Endpoint during Replication Settings template creation.</p>
    pub fn use_fips_endpoint(mut self, input: bool) -> Self {
        self.use_fips_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request to use Fips Endpoint during Replication Settings template creation.</p>
    pub fn set_use_fips_endpoint(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_fips_endpoint = input;
        self
    }
    /// <p>Request to use Fips Endpoint during Replication Settings template creation.</p>
    pub fn get_use_fips_endpoint(&self) -> &::std::option::Option<bool> {
        &self.use_fips_endpoint
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Request to configure tags during Replication Settings template creation.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Request to configure tags during Replication Settings template creation.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Request to configure tags during Replication Settings template creation.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateReplicationConfigurationTemplateInput`](crate::operation::create_replication_configuration_template::CreateReplicationConfigurationTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_replication_configuration_template::CreateReplicationConfigurationTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_replication_configuration_template::CreateReplicationConfigurationTemplateInput {
                staging_area_subnet_id: self.staging_area_subnet_id,
                associate_default_security_group: self.associate_default_security_group,
                replication_servers_security_groups_ids: self.replication_servers_security_groups_ids,
                replication_server_instance_type: self.replication_server_instance_type,
                use_dedicated_replication_server: self.use_dedicated_replication_server,
                default_large_staging_disk_type: self.default_large_staging_disk_type,
                ebs_encryption: self.ebs_encryption,
                ebs_encryption_key_arn: self.ebs_encryption_key_arn,
                bandwidth_throttling: self.bandwidth_throttling,
                data_plane_routing: self.data_plane_routing,
                create_public_ip: self.create_public_ip,
                staging_area_tags: self.staging_area_tags,
                use_fips_endpoint: self.use_fips_endpoint,
                tags: self.tags,
            },
        )
    }
}
impl ::std::fmt::Debug for CreateReplicationConfigurationTemplateInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateReplicationConfigurationTemplateInputBuilder");
        formatter.field("staging_area_subnet_id", &self.staging_area_subnet_id);
        formatter.field("associate_default_security_group", &self.associate_default_security_group);
        formatter.field("replication_servers_security_groups_ids", &self.replication_servers_security_groups_ids);
        formatter.field("replication_server_instance_type", &self.replication_server_instance_type);
        formatter.field("use_dedicated_replication_server", &self.use_dedicated_replication_server);
        formatter.field("default_large_staging_disk_type", &self.default_large_staging_disk_type);
        formatter.field("ebs_encryption", &self.ebs_encryption);
        formatter.field("ebs_encryption_key_arn", &self.ebs_encryption_key_arn);
        formatter.field("bandwidth_throttling", &self.bandwidth_throttling);
        formatter.field("data_plane_routing", &self.data_plane_routing);
        formatter.field("create_public_ip", &self.create_public_ip);
        formatter.field("staging_area_tags", &"*** Sensitive Data Redacted ***");
        formatter.field("use_fips_endpoint", &self.use_fips_endpoint);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
