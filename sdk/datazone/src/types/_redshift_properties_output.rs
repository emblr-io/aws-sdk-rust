// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Redshift properties.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RedshiftPropertiesOutput {
    /// <p>The storage in the Amazon Redshift properties.</p>
    pub storage: ::std::option::Option<crate::types::RedshiftStorageProperties>,
    /// <p>The Amazon Redshift credentials.</p>
    pub credentials: ::std::option::Option<crate::types::RedshiftCredentials>,
    /// <p>Specifies whether Amaon Redshift properties has a provisioned secret.</p>
    pub is_provisioned_secret: ::std::option::Option<bool>,
    /// <p>The jdbcIam URL of the Amazon Redshift properties.</p>
    pub jdbc_iam_url: ::std::option::Option<::std::string::String>,
    /// <p>The jdbcURL of the Amazon Redshift properties.</p>
    pub jdbc_url: ::std::option::Option<::std::string::String>,
    /// <p>The redshiftTempDir of the Amazon Redshift properties.</p>
    pub redshift_temp_dir: ::std::option::Option<::std::string::String>,
    /// <p>The lineage syn of the Amazon Redshift properties.</p>
    pub lineage_sync: ::std::option::Option<crate::types::RedshiftLineageSyncConfigurationOutput>,
    /// <p>The status in the Amazon Redshift properties.</p>
    pub status: ::std::option::Option<crate::types::ConnectionStatus>,
    /// <p>The Amazon Redshift database name.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
}
impl RedshiftPropertiesOutput {
    /// <p>The storage in the Amazon Redshift properties.</p>
    pub fn storage(&self) -> ::std::option::Option<&crate::types::RedshiftStorageProperties> {
        self.storage.as_ref()
    }
    /// <p>The Amazon Redshift credentials.</p>
    pub fn credentials(&self) -> ::std::option::Option<&crate::types::RedshiftCredentials> {
        self.credentials.as_ref()
    }
    /// <p>Specifies whether Amaon Redshift properties has a provisioned secret.</p>
    pub fn is_provisioned_secret(&self) -> ::std::option::Option<bool> {
        self.is_provisioned_secret
    }
    /// <p>The jdbcIam URL of the Amazon Redshift properties.</p>
    pub fn jdbc_iam_url(&self) -> ::std::option::Option<&str> {
        self.jdbc_iam_url.as_deref()
    }
    /// <p>The jdbcURL of the Amazon Redshift properties.</p>
    pub fn jdbc_url(&self) -> ::std::option::Option<&str> {
        self.jdbc_url.as_deref()
    }
    /// <p>The redshiftTempDir of the Amazon Redshift properties.</p>
    pub fn redshift_temp_dir(&self) -> ::std::option::Option<&str> {
        self.redshift_temp_dir.as_deref()
    }
    /// <p>The lineage syn of the Amazon Redshift properties.</p>
    pub fn lineage_sync(&self) -> ::std::option::Option<&crate::types::RedshiftLineageSyncConfigurationOutput> {
        self.lineage_sync.as_ref()
    }
    /// <p>The status in the Amazon Redshift properties.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ConnectionStatus> {
        self.status.as_ref()
    }
    /// <p>The Amazon Redshift database name.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
}
impl ::std::fmt::Debug for RedshiftPropertiesOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RedshiftPropertiesOutput");
        formatter.field("storage", &self.storage);
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("is_provisioned_secret", &self.is_provisioned_secret);
        formatter.field("jdbc_iam_url", &self.jdbc_iam_url);
        formatter.field("jdbc_url", &self.jdbc_url);
        formatter.field("redshift_temp_dir", &self.redshift_temp_dir);
        formatter.field("lineage_sync", &self.lineage_sync);
        formatter.field("status", &self.status);
        formatter.field("database_name", &self.database_name);
        formatter.finish()
    }
}
impl RedshiftPropertiesOutput {
    /// Creates a new builder-style object to manufacture [`RedshiftPropertiesOutput`](crate::types::RedshiftPropertiesOutput).
    pub fn builder() -> crate::types::builders::RedshiftPropertiesOutputBuilder {
        crate::types::builders::RedshiftPropertiesOutputBuilder::default()
    }
}

/// A builder for [`RedshiftPropertiesOutput`](crate::types::RedshiftPropertiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RedshiftPropertiesOutputBuilder {
    pub(crate) storage: ::std::option::Option<crate::types::RedshiftStorageProperties>,
    pub(crate) credentials: ::std::option::Option<crate::types::RedshiftCredentials>,
    pub(crate) is_provisioned_secret: ::std::option::Option<bool>,
    pub(crate) jdbc_iam_url: ::std::option::Option<::std::string::String>,
    pub(crate) jdbc_url: ::std::option::Option<::std::string::String>,
    pub(crate) redshift_temp_dir: ::std::option::Option<::std::string::String>,
    pub(crate) lineage_sync: ::std::option::Option<crate::types::RedshiftLineageSyncConfigurationOutput>,
    pub(crate) status: ::std::option::Option<crate::types::ConnectionStatus>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
}
impl RedshiftPropertiesOutputBuilder {
    /// <p>The storage in the Amazon Redshift properties.</p>
    pub fn storage(mut self, input: crate::types::RedshiftStorageProperties) -> Self {
        self.storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage in the Amazon Redshift properties.</p>
    pub fn set_storage(mut self, input: ::std::option::Option<crate::types::RedshiftStorageProperties>) -> Self {
        self.storage = input;
        self
    }
    /// <p>The storage in the Amazon Redshift properties.</p>
    pub fn get_storage(&self) -> &::std::option::Option<crate::types::RedshiftStorageProperties> {
        &self.storage
    }
    /// <p>The Amazon Redshift credentials.</p>
    pub fn credentials(mut self, input: crate::types::RedshiftCredentials) -> Self {
        self.credentials = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Redshift credentials.</p>
    pub fn set_credentials(mut self, input: ::std::option::Option<crate::types::RedshiftCredentials>) -> Self {
        self.credentials = input;
        self
    }
    /// <p>The Amazon Redshift credentials.</p>
    pub fn get_credentials(&self) -> &::std::option::Option<crate::types::RedshiftCredentials> {
        &self.credentials
    }
    /// <p>Specifies whether Amaon Redshift properties has a provisioned secret.</p>
    pub fn is_provisioned_secret(mut self, input: bool) -> Self {
        self.is_provisioned_secret = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether Amaon Redshift properties has a provisioned secret.</p>
    pub fn set_is_provisioned_secret(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_provisioned_secret = input;
        self
    }
    /// <p>Specifies whether Amaon Redshift properties has a provisioned secret.</p>
    pub fn get_is_provisioned_secret(&self) -> &::std::option::Option<bool> {
        &self.is_provisioned_secret
    }
    /// <p>The jdbcIam URL of the Amazon Redshift properties.</p>
    pub fn jdbc_iam_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.jdbc_iam_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The jdbcIam URL of the Amazon Redshift properties.</p>
    pub fn set_jdbc_iam_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.jdbc_iam_url = input;
        self
    }
    /// <p>The jdbcIam URL of the Amazon Redshift properties.</p>
    pub fn get_jdbc_iam_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.jdbc_iam_url
    }
    /// <p>The jdbcURL of the Amazon Redshift properties.</p>
    pub fn jdbc_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.jdbc_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The jdbcURL of the Amazon Redshift properties.</p>
    pub fn set_jdbc_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.jdbc_url = input;
        self
    }
    /// <p>The jdbcURL of the Amazon Redshift properties.</p>
    pub fn get_jdbc_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.jdbc_url
    }
    /// <p>The redshiftTempDir of the Amazon Redshift properties.</p>
    pub fn redshift_temp_dir(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.redshift_temp_dir = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The redshiftTempDir of the Amazon Redshift properties.</p>
    pub fn set_redshift_temp_dir(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.redshift_temp_dir = input;
        self
    }
    /// <p>The redshiftTempDir of the Amazon Redshift properties.</p>
    pub fn get_redshift_temp_dir(&self) -> &::std::option::Option<::std::string::String> {
        &self.redshift_temp_dir
    }
    /// <p>The lineage syn of the Amazon Redshift properties.</p>
    pub fn lineage_sync(mut self, input: crate::types::RedshiftLineageSyncConfigurationOutput) -> Self {
        self.lineage_sync = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lineage syn of the Amazon Redshift properties.</p>
    pub fn set_lineage_sync(mut self, input: ::std::option::Option<crate::types::RedshiftLineageSyncConfigurationOutput>) -> Self {
        self.lineage_sync = input;
        self
    }
    /// <p>The lineage syn of the Amazon Redshift properties.</p>
    pub fn get_lineage_sync(&self) -> &::std::option::Option<crate::types::RedshiftLineageSyncConfigurationOutput> {
        &self.lineage_sync
    }
    /// <p>The status in the Amazon Redshift properties.</p>
    pub fn status(mut self, input: crate::types::ConnectionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status in the Amazon Redshift properties.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ConnectionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status in the Amazon Redshift properties.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ConnectionStatus> {
        &self.status
    }
    /// <p>The Amazon Redshift database name.</p>
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Redshift database name.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The Amazon Redshift database name.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// Consumes the builder and constructs a [`RedshiftPropertiesOutput`](crate::types::RedshiftPropertiesOutput).
    pub fn build(self) -> crate::types::RedshiftPropertiesOutput {
        crate::types::RedshiftPropertiesOutput {
            storage: self.storage,
            credentials: self.credentials,
            is_provisioned_secret: self.is_provisioned_secret,
            jdbc_iam_url: self.jdbc_iam_url,
            jdbc_url: self.jdbc_url,
            redshift_temp_dir: self.redshift_temp_dir,
            lineage_sync: self.lineage_sync,
            status: self.status,
            database_name: self.database_name,
        }
    }
}
impl ::std::fmt::Debug for RedshiftPropertiesOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RedshiftPropertiesOutputBuilder");
        formatter.field("storage", &self.storage);
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("is_provisioned_secret", &self.is_provisioned_secret);
        formatter.field("jdbc_iam_url", &self.jdbc_iam_url);
        formatter.field("jdbc_url", &self.jdbc_url);
        formatter.field("redshift_temp_dir", &self.redshift_temp_dir);
        formatter.field("lineage_sync", &self.lineage_sync);
        formatter.field("status", &self.status);
        formatter.field("database_name", &self.database_name);
        formatter.finish()
    }
}
