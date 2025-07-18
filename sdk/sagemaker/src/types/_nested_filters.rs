// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of nested <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Filter.html">Filter</a> objects. A resource must satisfy the conditions of all filters to be included in the results returned from the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API.</p>
/// <p>For example, to filter on a training job's <code>InputDataConfig</code> property with a specific channel name and <code>S3Uri</code> prefix, define the following filters:</p>
/// <ul>
/// <li>
/// <p><code>'{Name:"InputDataConfig.ChannelName", "Operator":"Equals", "Value":"train"}',</code></p></li>
/// <li>
/// <p><code>'{Name:"InputDataConfig.DataSource.S3DataSource.S3Uri", "Operator":"Contains", "Value":"mybucket/catdata"}'</code></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NestedFilters {
    /// <p>The name of the property to use in the nested filters. The value must match a listed property name, such as <code>InputDataConfig</code>.</p>
    pub nested_property_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of filters. Each filter acts on a property. Filters must contain at least one <code>Filters</code> value. For example, a <code>NestedFilters</code> call might include a filter on the <code>PropertyName</code> parameter of the <code>InputDataConfig</code> property: <code>InputDataConfig.DataSource.S3DataSource.S3Uri</code>.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl NestedFilters {
    /// <p>The name of the property to use in the nested filters. The value must match a listed property name, such as <code>InputDataConfig</code>.</p>
    pub fn nested_property_name(&self) -> ::std::option::Option<&str> {
        self.nested_property_name.as_deref()
    }
    /// <p>A list of filters. Each filter acts on a property. Filters must contain at least one <code>Filters</code> value. For example, a <code>NestedFilters</code> call might include a filter on the <code>PropertyName</code> parameter of the <code>InputDataConfig</code> property: <code>InputDataConfig.DataSource.S3DataSource.S3Uri</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl NestedFilters {
    /// Creates a new builder-style object to manufacture [`NestedFilters`](crate::types::NestedFilters).
    pub fn builder() -> crate::types::builders::NestedFiltersBuilder {
        crate::types::builders::NestedFiltersBuilder::default()
    }
}

/// A builder for [`NestedFilters`](crate::types::NestedFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NestedFiltersBuilder {
    pub(crate) nested_property_name: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl NestedFiltersBuilder {
    /// <p>The name of the property to use in the nested filters. The value must match a listed property name, such as <code>InputDataConfig</code>.</p>
    /// This field is required.
    pub fn nested_property_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.nested_property_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the property to use in the nested filters. The value must match a listed property name, such as <code>InputDataConfig</code>.</p>
    pub fn set_nested_property_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.nested_property_name = input;
        self
    }
    /// <p>The name of the property to use in the nested filters. The value must match a listed property name, such as <code>InputDataConfig</code>.</p>
    pub fn get_nested_property_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.nested_property_name
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>A list of filters. Each filter acts on a property. Filters must contain at least one <code>Filters</code> value. For example, a <code>NestedFilters</code> call might include a filter on the <code>PropertyName</code> parameter of the <code>InputDataConfig</code> property: <code>InputDataConfig.DataSource.S3DataSource.S3Uri</code>.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of filters. Each filter acts on a property. Filters must contain at least one <code>Filters</code> value. For example, a <code>NestedFilters</code> call might include a filter on the <code>PropertyName</code> parameter of the <code>InputDataConfig</code> property: <code>InputDataConfig.DataSource.S3DataSource.S3Uri</code>.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A list of filters. Each filter acts on a property. Filters must contain at least one <code>Filters</code> value. For example, a <code>NestedFilters</code> call might include a filter on the <code>PropertyName</code> parameter of the <code>InputDataConfig</code> property: <code>InputDataConfig.DataSource.S3DataSource.S3Uri</code>.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`NestedFilters`](crate::types::NestedFilters).
    pub fn build(self) -> crate::types::NestedFilters {
        crate::types::NestedFilters {
            nested_property_name: self.nested_property_name,
            filters: self.filters,
        }
    }
}
