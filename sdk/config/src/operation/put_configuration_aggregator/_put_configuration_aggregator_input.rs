// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutConfigurationAggregatorInput {
    /// <p>The name of the configuration aggregator.</p>
    pub configuration_aggregator_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of AccountAggregationSource object.</p>
    pub account_aggregation_sources: ::std::option::Option<::std::vec::Vec<crate::types::AccountAggregationSource>>,
    /// <p>An OrganizationAggregationSource object.</p>
    pub organization_aggregation_source: ::std::option::Option<crate::types::OrganizationAggregationSource>,
    /// <p>An array of tag object.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>An object to filter configuration recorders in an aggregator. Either <code>ResourceType</code> or <code>ServicePrincipal</code> is required.</p>
    pub aggregator_filters: ::std::option::Option<crate::types::AggregatorFilters>,
}
impl PutConfigurationAggregatorInput {
    /// <p>The name of the configuration aggregator.</p>
    pub fn configuration_aggregator_name(&self) -> ::std::option::Option<&str> {
        self.configuration_aggregator_name.as_deref()
    }
    /// <p>A list of AccountAggregationSource object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_aggregation_sources.is_none()`.
    pub fn account_aggregation_sources(&self) -> &[crate::types::AccountAggregationSource] {
        self.account_aggregation_sources.as_deref().unwrap_or_default()
    }
    /// <p>An OrganizationAggregationSource object.</p>
    pub fn organization_aggregation_source(&self) -> ::std::option::Option<&crate::types::OrganizationAggregationSource> {
        self.organization_aggregation_source.as_ref()
    }
    /// <p>An array of tag object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>An object to filter configuration recorders in an aggregator. Either <code>ResourceType</code> or <code>ServicePrincipal</code> is required.</p>
    pub fn aggregator_filters(&self) -> ::std::option::Option<&crate::types::AggregatorFilters> {
        self.aggregator_filters.as_ref()
    }
}
impl PutConfigurationAggregatorInput {
    /// Creates a new builder-style object to manufacture [`PutConfigurationAggregatorInput`](crate::operation::put_configuration_aggregator::PutConfigurationAggregatorInput).
    pub fn builder() -> crate::operation::put_configuration_aggregator::builders::PutConfigurationAggregatorInputBuilder {
        crate::operation::put_configuration_aggregator::builders::PutConfigurationAggregatorInputBuilder::default()
    }
}

/// A builder for [`PutConfigurationAggregatorInput`](crate::operation::put_configuration_aggregator::PutConfigurationAggregatorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutConfigurationAggregatorInputBuilder {
    pub(crate) configuration_aggregator_name: ::std::option::Option<::std::string::String>,
    pub(crate) account_aggregation_sources: ::std::option::Option<::std::vec::Vec<crate::types::AccountAggregationSource>>,
    pub(crate) organization_aggregation_source: ::std::option::Option<crate::types::OrganizationAggregationSource>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) aggregator_filters: ::std::option::Option<crate::types::AggregatorFilters>,
}
impl PutConfigurationAggregatorInputBuilder {
    /// <p>The name of the configuration aggregator.</p>
    /// This field is required.
    pub fn configuration_aggregator_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_aggregator_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration aggregator.</p>
    pub fn set_configuration_aggregator_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_aggregator_name = input;
        self
    }
    /// <p>The name of the configuration aggregator.</p>
    pub fn get_configuration_aggregator_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_aggregator_name
    }
    /// Appends an item to `account_aggregation_sources`.
    ///
    /// To override the contents of this collection use [`set_account_aggregation_sources`](Self::set_account_aggregation_sources).
    ///
    /// <p>A list of AccountAggregationSource object.</p>
    pub fn account_aggregation_sources(mut self, input: crate::types::AccountAggregationSource) -> Self {
        let mut v = self.account_aggregation_sources.unwrap_or_default();
        v.push(input);
        self.account_aggregation_sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of AccountAggregationSource object.</p>
    pub fn set_account_aggregation_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AccountAggregationSource>>) -> Self {
        self.account_aggregation_sources = input;
        self
    }
    /// <p>A list of AccountAggregationSource object.</p>
    pub fn get_account_aggregation_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AccountAggregationSource>> {
        &self.account_aggregation_sources
    }
    /// <p>An OrganizationAggregationSource object.</p>
    pub fn organization_aggregation_source(mut self, input: crate::types::OrganizationAggregationSource) -> Self {
        self.organization_aggregation_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>An OrganizationAggregationSource object.</p>
    pub fn set_organization_aggregation_source(mut self, input: ::std::option::Option<crate::types::OrganizationAggregationSource>) -> Self {
        self.organization_aggregation_source = input;
        self
    }
    /// <p>An OrganizationAggregationSource object.</p>
    pub fn get_organization_aggregation_source(&self) -> &::std::option::Option<crate::types::OrganizationAggregationSource> {
        &self.organization_aggregation_source
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of tag object.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of tag object.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of tag object.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>An object to filter configuration recorders in an aggregator. Either <code>ResourceType</code> or <code>ServicePrincipal</code> is required.</p>
    pub fn aggregator_filters(mut self, input: crate::types::AggregatorFilters) -> Self {
        self.aggregator_filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object to filter configuration recorders in an aggregator. Either <code>ResourceType</code> or <code>ServicePrincipal</code> is required.</p>
    pub fn set_aggregator_filters(mut self, input: ::std::option::Option<crate::types::AggregatorFilters>) -> Self {
        self.aggregator_filters = input;
        self
    }
    /// <p>An object to filter configuration recorders in an aggregator. Either <code>ResourceType</code> or <code>ServicePrincipal</code> is required.</p>
    pub fn get_aggregator_filters(&self) -> &::std::option::Option<crate::types::AggregatorFilters> {
        &self.aggregator_filters
    }
    /// Consumes the builder and constructs a [`PutConfigurationAggregatorInput`](crate::operation::put_configuration_aggregator::PutConfigurationAggregatorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_configuration_aggregator::PutConfigurationAggregatorInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_configuration_aggregator::PutConfigurationAggregatorInput {
            configuration_aggregator_name: self.configuration_aggregator_name,
            account_aggregation_sources: self.account_aggregation_sources,
            organization_aggregation_source: self.organization_aggregation_source,
            tags: self.tags,
            aggregator_filters: self.aggregator_filters,
        })
    }
}
