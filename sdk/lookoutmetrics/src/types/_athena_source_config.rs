// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an Amazon Athena datasource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AthenaSourceConfig {
    /// <p>An IAM role that gives Amazon Lookout for Metrics permission to access the data.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The database's name.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The database's data catalog.</p>
    pub data_catalog: ::std::option::Option<::std::string::String>,
    /// <p>The database's table name.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>The database's work group name.</p>
    pub work_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The database's results path.</p>
    pub s3_results_path: ::std::option::Option<::std::string::String>,
    /// <p>Settings for backtest mode.</p>
    pub back_test_configuration: ::std::option::Option<crate::types::BackTestConfiguration>,
}
impl AthenaSourceConfig {
    /// <p>An IAM role that gives Amazon Lookout for Metrics permission to access the data.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The database's name.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The database's data catalog.</p>
    pub fn data_catalog(&self) -> ::std::option::Option<&str> {
        self.data_catalog.as_deref()
    }
    /// <p>The database's table name.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>The database's work group name.</p>
    pub fn work_group_name(&self) -> ::std::option::Option<&str> {
        self.work_group_name.as_deref()
    }
    /// <p>The database's results path.</p>
    pub fn s3_results_path(&self) -> ::std::option::Option<&str> {
        self.s3_results_path.as_deref()
    }
    /// <p>Settings for backtest mode.</p>
    pub fn back_test_configuration(&self) -> ::std::option::Option<&crate::types::BackTestConfiguration> {
        self.back_test_configuration.as_ref()
    }
}
impl AthenaSourceConfig {
    /// Creates a new builder-style object to manufacture [`AthenaSourceConfig`](crate::types::AthenaSourceConfig).
    pub fn builder() -> crate::types::builders::AthenaSourceConfigBuilder {
        crate::types::builders::AthenaSourceConfigBuilder::default()
    }
}

/// A builder for [`AthenaSourceConfig`](crate::types::AthenaSourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AthenaSourceConfigBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_catalog: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) work_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) s3_results_path: ::std::option::Option<::std::string::String>,
    pub(crate) back_test_configuration: ::std::option::Option<crate::types::BackTestConfiguration>,
}
impl AthenaSourceConfigBuilder {
    /// <p>An IAM role that gives Amazon Lookout for Metrics permission to access the data.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An IAM role that gives Amazon Lookout for Metrics permission to access the data.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>An IAM role that gives Amazon Lookout for Metrics permission to access the data.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The database's name.</p>
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database's name.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The database's name.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The database's data catalog.</p>
    pub fn data_catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database's data catalog.</p>
    pub fn set_data_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_catalog = input;
        self
    }
    /// <p>The database's data catalog.</p>
    pub fn get_data_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_catalog
    }
    /// <p>The database's table name.</p>
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database's table name.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The database's table name.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>The database's work group name.</p>
    pub fn work_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.work_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database's work group name.</p>
    pub fn set_work_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.work_group_name = input;
        self
    }
    /// <p>The database's work group name.</p>
    pub fn get_work_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.work_group_name
    }
    /// <p>The database's results path.</p>
    pub fn s3_results_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_results_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database's results path.</p>
    pub fn set_s3_results_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_results_path = input;
        self
    }
    /// <p>The database's results path.</p>
    pub fn get_s3_results_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_results_path
    }
    /// <p>Settings for backtest mode.</p>
    pub fn back_test_configuration(mut self, input: crate::types::BackTestConfiguration) -> Self {
        self.back_test_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings for backtest mode.</p>
    pub fn set_back_test_configuration(mut self, input: ::std::option::Option<crate::types::BackTestConfiguration>) -> Self {
        self.back_test_configuration = input;
        self
    }
    /// <p>Settings for backtest mode.</p>
    pub fn get_back_test_configuration(&self) -> &::std::option::Option<crate::types::BackTestConfiguration> {
        &self.back_test_configuration
    }
    /// Consumes the builder and constructs a [`AthenaSourceConfig`](crate::types::AthenaSourceConfig).
    pub fn build(self) -> crate::types::AthenaSourceConfig {
        crate::types::AthenaSourceConfig {
            role_arn: self.role_arn,
            database_name: self.database_name,
            data_catalog: self.data_catalog,
            table_name: self.table_name,
            work_group_name: self.work_group_name,
            s3_results_path: self.s3_results_path,
            back_test_configuration: self.back_test_configuration,
        }
    }
}
