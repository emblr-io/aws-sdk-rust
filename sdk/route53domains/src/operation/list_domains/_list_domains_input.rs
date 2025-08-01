// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The ListDomains request includes the following elements.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDomainsInput {
    /// <p>A complex type that contains information about the filters applied during the <code>ListDomains</code> request. The filter conditions can include domain name and domain expiration.</p>
    pub filter_conditions: ::std::option::Option<::std::vec::Vec<crate::types::FilterCondition>>,
    /// <p>A complex type that contains information about the requested ordering of domains in the returned list.</p>
    pub sort_condition: ::std::option::Option<crate::types::SortCondition>,
    /// <p>For an initial request for a list of domains, omit this element. If the number of domains that are associated with the current Amazon Web Services account is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional domains. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Constraints: The marker must match the value specified in the previous request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Number of domains to be returned.</p>
    /// <p>Default: 20</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListDomainsInput {
    /// <p>A complex type that contains information about the filters applied during the <code>ListDomains</code> request. The filter conditions can include domain name and domain expiration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_conditions.is_none()`.
    pub fn filter_conditions(&self) -> &[crate::types::FilterCondition] {
        self.filter_conditions.as_deref().unwrap_or_default()
    }
    /// <p>A complex type that contains information about the requested ordering of domains in the returned list.</p>
    pub fn sort_condition(&self) -> ::std::option::Option<&crate::types::SortCondition> {
        self.sort_condition.as_ref()
    }
    /// <p>For an initial request for a list of domains, omit this element. If the number of domains that are associated with the current Amazon Web Services account is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional domains. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Constraints: The marker must match the value specified in the previous request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Number of domains to be returned.</p>
    /// <p>Default: 20</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListDomainsInput {
    /// Creates a new builder-style object to manufacture [`ListDomainsInput`](crate::operation::list_domains::ListDomainsInput).
    pub fn builder() -> crate::operation::list_domains::builders::ListDomainsInputBuilder {
        crate::operation::list_domains::builders::ListDomainsInputBuilder::default()
    }
}

/// A builder for [`ListDomainsInput`](crate::operation::list_domains::ListDomainsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDomainsInputBuilder {
    pub(crate) filter_conditions: ::std::option::Option<::std::vec::Vec<crate::types::FilterCondition>>,
    pub(crate) sort_condition: ::std::option::Option<crate::types::SortCondition>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListDomainsInputBuilder {
    /// Appends an item to `filter_conditions`.
    ///
    /// To override the contents of this collection use [`set_filter_conditions`](Self::set_filter_conditions).
    ///
    /// <p>A complex type that contains information about the filters applied during the <code>ListDomains</code> request. The filter conditions can include domain name and domain expiration.</p>
    pub fn filter_conditions(mut self, input: crate::types::FilterCondition) -> Self {
        let mut v = self.filter_conditions.unwrap_or_default();
        v.push(input);
        self.filter_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A complex type that contains information about the filters applied during the <code>ListDomains</code> request. The filter conditions can include domain name and domain expiration.</p>
    pub fn set_filter_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterCondition>>) -> Self {
        self.filter_conditions = input;
        self
    }
    /// <p>A complex type that contains information about the filters applied during the <code>ListDomains</code> request. The filter conditions can include domain name and domain expiration.</p>
    pub fn get_filter_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterCondition>> {
        &self.filter_conditions
    }
    /// <p>A complex type that contains information about the requested ordering of domains in the returned list.</p>
    pub fn sort_condition(mut self, input: crate::types::SortCondition) -> Self {
        self.sort_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains information about the requested ordering of domains in the returned list.</p>
    pub fn set_sort_condition(mut self, input: ::std::option::Option<crate::types::SortCondition>) -> Self {
        self.sort_condition = input;
        self
    }
    /// <p>A complex type that contains information about the requested ordering of domains in the returned list.</p>
    pub fn get_sort_condition(&self) -> &::std::option::Option<crate::types::SortCondition> {
        &self.sort_condition
    }
    /// <p>For an initial request for a list of domains, omit this element. If the number of domains that are associated with the current Amazon Web Services account is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional domains. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Constraints: The marker must match the value specified in the previous request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For an initial request for a list of domains, omit this element. If the number of domains that are associated with the current Amazon Web Services account is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional domains. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Constraints: The marker must match the value specified in the previous request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>For an initial request for a list of domains, omit this element. If the number of domains that are associated with the current Amazon Web Services account is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional domains. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Constraints: The marker must match the value specified in the previous request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>Number of domains to be returned.</p>
    /// <p>Default: 20</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>Number of domains to be returned.</p>
    /// <p>Default: 20</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>Number of domains to be returned.</p>
    /// <p>Default: 20</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListDomainsInput`](crate::operation::list_domains::ListDomainsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_domains::ListDomainsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_domains::ListDomainsInput {
            filter_conditions: self.filter_conditions,
            sort_condition: self.sort_condition,
            marker: self.marker,
            max_items: self.max_items,
        })
    }
}
