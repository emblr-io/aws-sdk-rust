// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMetadataModelImportsInput {
    /// <p>The migration project name or Amazon Resource Name (ARN).</p>
    pub migration_project_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Filters applied to the metadata model imports described in the form of key-value pairs.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>Specifies the unique pagination token that makes it possible to display the next page of results. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    /// <p>If <code>Marker</code> is returned by a previous response, there are more results available. The value of <code>Marker</code> is a unique pagination token for each page. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>A paginated list of metadata model imports.</p>
    pub max_records: ::std::option::Option<i32>,
}
impl DescribeMetadataModelImportsInput {
    /// <p>The migration project name or Amazon Resource Name (ARN).</p>
    pub fn migration_project_identifier(&self) -> ::std::option::Option<&str> {
        self.migration_project_identifier.as_deref()
    }
    /// <p>Filters applied to the metadata model imports described in the form of key-value pairs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the unique pagination token that makes it possible to display the next page of results. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    /// <p>If <code>Marker</code> is returned by a previous response, there are more results available. The value of <code>Marker</code> is a unique pagination token for each page. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>A paginated list of metadata model imports.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
}
impl DescribeMetadataModelImportsInput {
    /// Creates a new builder-style object to manufacture [`DescribeMetadataModelImportsInput`](crate::operation::describe_metadata_model_imports::DescribeMetadataModelImportsInput).
    pub fn builder() -> crate::operation::describe_metadata_model_imports::builders::DescribeMetadataModelImportsInputBuilder {
        crate::operation::describe_metadata_model_imports::builders::DescribeMetadataModelImportsInputBuilder::default()
    }
}

/// A builder for [`DescribeMetadataModelImportsInput`](crate::operation::describe_metadata_model_imports::DescribeMetadataModelImportsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMetadataModelImportsInputBuilder {
    pub(crate) migration_project_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
}
impl DescribeMetadataModelImportsInputBuilder {
    /// <p>The migration project name or Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn migration_project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.migration_project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The migration project name or Amazon Resource Name (ARN).</p>
    pub fn set_migration_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.migration_project_identifier = input;
        self
    }
    /// <p>The migration project name or Amazon Resource Name (ARN).</p>
    pub fn get_migration_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.migration_project_identifier
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Filters applied to the metadata model imports described in the form of key-value pairs.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters applied to the metadata model imports described in the form of key-value pairs.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Filters applied to the metadata model imports described in the form of key-value pairs.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>Specifies the unique pagination token that makes it possible to display the next page of results. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    /// <p>If <code>Marker</code> is returned by a previous response, there are more results available. The value of <code>Marker</code> is a unique pagination token for each page. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the unique pagination token that makes it possible to display the next page of results. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    /// <p>If <code>Marker</code> is returned by a previous response, there are more results available. The value of <code>Marker</code> is a unique pagination token for each page. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Specifies the unique pagination token that makes it possible to display the next page of results. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    /// <p>If <code>Marker</code> is returned by a previous response, there are more results available. The value of <code>Marker</code> is a unique pagination token for each page. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>A paginated list of metadata model imports.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>A paginated list of metadata model imports.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>A paginated list of metadata model imports.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// Consumes the builder and constructs a [`DescribeMetadataModelImportsInput`](crate::operation::describe_metadata_model_imports::DescribeMetadataModelImportsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_metadata_model_imports::DescribeMetadataModelImportsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_metadata_model_imports::DescribeMetadataModelImportsInput {
            migration_project_identifier: self.migration_project_identifier,
            filters: self.filters,
            marker: self.marker,
            max_records: self.max_records,
        })
    }
}
