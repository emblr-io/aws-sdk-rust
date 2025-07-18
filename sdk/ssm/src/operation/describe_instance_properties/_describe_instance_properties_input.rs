// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstancePropertiesInput {
    /// <p>An array of instance property filters.</p>
    pub instance_property_filter_list: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyFilter>>,
    /// <p>The request filters to use with the operator.</p>
    pub filters_with_operator: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyStringFilter>>,
    /// <p>The maximum number of items to return for the call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token provided by a previous request to use to return the next set of properties.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeInstancePropertiesInput {
    /// <p>An array of instance property filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_property_filter_list.is_none()`.
    pub fn instance_property_filter_list(&self) -> &[crate::types::InstancePropertyFilter] {
        self.instance_property_filter_list.as_deref().unwrap_or_default()
    }
    /// <p>The request filters to use with the operator.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters_with_operator.is_none()`.
    pub fn filters_with_operator(&self) -> &[crate::types::InstancePropertyStringFilter] {
        self.filters_with_operator.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of items to return for the call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token provided by a previous request to use to return the next set of properties.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeInstancePropertiesInput {
    /// Creates a new builder-style object to manufacture [`DescribeInstancePropertiesInput`](crate::operation::describe_instance_properties::DescribeInstancePropertiesInput).
    pub fn builder() -> crate::operation::describe_instance_properties::builders::DescribeInstancePropertiesInputBuilder {
        crate::operation::describe_instance_properties::builders::DescribeInstancePropertiesInputBuilder::default()
    }
}

/// A builder for [`DescribeInstancePropertiesInput`](crate::operation::describe_instance_properties::DescribeInstancePropertiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstancePropertiesInputBuilder {
    pub(crate) instance_property_filter_list: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyFilter>>,
    pub(crate) filters_with_operator: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyStringFilter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeInstancePropertiesInputBuilder {
    /// Appends an item to `instance_property_filter_list`.
    ///
    /// To override the contents of this collection use [`set_instance_property_filter_list`](Self::set_instance_property_filter_list).
    ///
    /// <p>An array of instance property filters.</p>
    pub fn instance_property_filter_list(mut self, input: crate::types::InstancePropertyFilter) -> Self {
        let mut v = self.instance_property_filter_list.unwrap_or_default();
        v.push(input);
        self.instance_property_filter_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of instance property filters.</p>
    pub fn set_instance_property_filter_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyFilter>>) -> Self {
        self.instance_property_filter_list = input;
        self
    }
    /// <p>An array of instance property filters.</p>
    pub fn get_instance_property_filter_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyFilter>> {
        &self.instance_property_filter_list
    }
    /// Appends an item to `filters_with_operator`.
    ///
    /// To override the contents of this collection use [`set_filters_with_operator`](Self::set_filters_with_operator).
    ///
    /// <p>The request filters to use with the operator.</p>
    pub fn filters_with_operator(mut self, input: crate::types::InstancePropertyStringFilter) -> Self {
        let mut v = self.filters_with_operator.unwrap_or_default();
        v.push(input);
        self.filters_with_operator = ::std::option::Option::Some(v);
        self
    }
    /// <p>The request filters to use with the operator.</p>
    pub fn set_filters_with_operator(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyStringFilter>>) -> Self {
        self.filters_with_operator = input;
        self
    }
    /// <p>The request filters to use with the operator.</p>
    pub fn get_filters_with_operator(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstancePropertyStringFilter>> {
        &self.filters_with_operator
    }
    /// <p>The maximum number of items to return for the call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for the call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for the call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token provided by a previous request to use to return the next set of properties.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token provided by a previous request to use to return the next set of properties.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token provided by a previous request to use to return the next set of properties.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeInstancePropertiesInput`](crate::operation::describe_instance_properties::DescribeInstancePropertiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_instance_properties::DescribeInstancePropertiesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_instance_properties::DescribeInstancePropertiesInput {
            instance_property_filter_list: self.instance_property_filter_list,
            filters_with_operator: self.filters_with_operator,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
