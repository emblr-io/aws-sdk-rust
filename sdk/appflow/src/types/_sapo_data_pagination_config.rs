// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Sets the page size for each <i>concurrent process</i> that transfers OData records from your SAP instance. A concurrent process is query that retrieves a batch of records as part of a flow run. Amazon AppFlow can run multiple concurrent processes in parallel to transfer data faster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SapoDataPaginationConfig {
    /// <p>The maximum number of records that Amazon AppFlow receives in each page of the response from your SAP application. For transfers of OData records, the maximum page size is 3,000. For transfers of data that comes from an ODP provider, the maximum page size is 10,000.</p>
    pub max_page_size: i32,
}
impl SapoDataPaginationConfig {
    /// <p>The maximum number of records that Amazon AppFlow receives in each page of the response from your SAP application. For transfers of OData records, the maximum page size is 3,000. For transfers of data that comes from an ODP provider, the maximum page size is 10,000.</p>
    pub fn max_page_size(&self) -> i32 {
        self.max_page_size
    }
}
impl SapoDataPaginationConfig {
    /// Creates a new builder-style object to manufacture [`SapoDataPaginationConfig`](crate::types::SapoDataPaginationConfig).
    pub fn builder() -> crate::types::builders::SapoDataPaginationConfigBuilder {
        crate::types::builders::SapoDataPaginationConfigBuilder::default()
    }
}

/// A builder for [`SapoDataPaginationConfig`](crate::types::SapoDataPaginationConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SapoDataPaginationConfigBuilder {
    pub(crate) max_page_size: ::std::option::Option<i32>,
}
impl SapoDataPaginationConfigBuilder {
    /// <p>The maximum number of records that Amazon AppFlow receives in each page of the response from your SAP application. For transfers of OData records, the maximum page size is 3,000. For transfers of data that comes from an ODP provider, the maximum page size is 10,000.</p>
    /// This field is required.
    pub fn max_page_size(mut self, input: i32) -> Self {
        self.max_page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of records that Amazon AppFlow receives in each page of the response from your SAP application. For transfers of OData records, the maximum page size is 3,000. For transfers of data that comes from an ODP provider, the maximum page size is 10,000.</p>
    pub fn set_max_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_page_size = input;
        self
    }
    /// <p>The maximum number of records that Amazon AppFlow receives in each page of the response from your SAP application. For transfers of OData records, the maximum page size is 3,000. For transfers of data that comes from an ODP provider, the maximum page size is 10,000.</p>
    pub fn get_max_page_size(&self) -> &::std::option::Option<i32> {
        &self.max_page_size
    }
    /// Consumes the builder and constructs a [`SapoDataPaginationConfig`](crate::types::SapoDataPaginationConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`max_page_size`](crate::types::builders::SapoDataPaginationConfigBuilder::max_page_size)
    pub fn build(self) -> ::std::result::Result<crate::types::SapoDataPaginationConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SapoDataPaginationConfig {
            max_page_size: self.max_page_size.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_page_size",
                    "max_page_size was not specified but it is required when building SapoDataPaginationConfig",
                )
            })?,
        })
    }
}
