// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information on the result of usage based on data source type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UsageDataSourceResult {
    /// <p>The data source type that generated usage.</p>
    pub data_source: ::std::option::Option<crate::types::DataSource>,
    /// <p>Represents the total of usage for the specified data source.</p>
    pub total: ::std::option::Option<crate::types::Total>,
}
impl UsageDataSourceResult {
    /// <p>The data source type that generated usage.</p>
    pub fn data_source(&self) -> ::std::option::Option<&crate::types::DataSource> {
        self.data_source.as_ref()
    }
    /// <p>Represents the total of usage for the specified data source.</p>
    pub fn total(&self) -> ::std::option::Option<&crate::types::Total> {
        self.total.as_ref()
    }
}
impl UsageDataSourceResult {
    /// Creates a new builder-style object to manufacture [`UsageDataSourceResult`](crate::types::UsageDataSourceResult).
    pub fn builder() -> crate::types::builders::UsageDataSourceResultBuilder {
        crate::types::builders::UsageDataSourceResultBuilder::default()
    }
}

/// A builder for [`UsageDataSourceResult`](crate::types::UsageDataSourceResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UsageDataSourceResultBuilder {
    pub(crate) data_source: ::std::option::Option<crate::types::DataSource>,
    pub(crate) total: ::std::option::Option<crate::types::Total>,
}
impl UsageDataSourceResultBuilder {
    /// <p>The data source type that generated usage.</p>
    pub fn data_source(mut self, input: crate::types::DataSource) -> Self {
        self.data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data source type that generated usage.</p>
    pub fn set_data_source(mut self, input: ::std::option::Option<crate::types::DataSource>) -> Self {
        self.data_source = input;
        self
    }
    /// <p>The data source type that generated usage.</p>
    pub fn get_data_source(&self) -> &::std::option::Option<crate::types::DataSource> {
        &self.data_source
    }
    /// <p>Represents the total of usage for the specified data source.</p>
    pub fn total(mut self, input: crate::types::Total) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the total of usage for the specified data source.</p>
    pub fn set_total(mut self, input: ::std::option::Option<crate::types::Total>) -> Self {
        self.total = input;
        self
    }
    /// <p>Represents the total of usage for the specified data source.</p>
    pub fn get_total(&self) -> &::std::option::Option<crate::types::Total> {
        &self.total
    }
    /// Consumes the builder and constructs a [`UsageDataSourceResult`](crate::types::UsageDataSourceResult).
    pub fn build(self) -> crate::types::UsageDataSourceResult {
        crate::types::UsageDataSourceResult {
            data_source: self.data_source,
            total: self.total,
        }
    }
}
