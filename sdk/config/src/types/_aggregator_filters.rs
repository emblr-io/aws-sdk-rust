// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object to filter the data you specify for an aggregator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AggregatorFilters {
    /// <p>An object to filter the configuration recorders based on the resource types in scope for recording.</p>
    pub resource_type: ::std::option::Option<crate::types::AggregatorFilterResourceType>,
    /// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
    pub service_principal: ::std::option::Option<crate::types::AggregatorFilterServicePrincipal>,
}
impl AggregatorFilters {
    /// <p>An object to filter the configuration recorders based on the resource types in scope for recording.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::AggregatorFilterResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
    pub fn service_principal(&self) -> ::std::option::Option<&crate::types::AggregatorFilterServicePrincipal> {
        self.service_principal.as_ref()
    }
}
impl AggregatorFilters {
    /// Creates a new builder-style object to manufacture [`AggregatorFilters`](crate::types::AggregatorFilters).
    pub fn builder() -> crate::types::builders::AggregatorFiltersBuilder {
        crate::types::builders::AggregatorFiltersBuilder::default()
    }
}

/// A builder for [`AggregatorFilters`](crate::types::AggregatorFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AggregatorFiltersBuilder {
    pub(crate) resource_type: ::std::option::Option<crate::types::AggregatorFilterResourceType>,
    pub(crate) service_principal: ::std::option::Option<crate::types::AggregatorFilterServicePrincipal>,
}
impl AggregatorFiltersBuilder {
    /// <p>An object to filter the configuration recorders based on the resource types in scope for recording.</p>
    pub fn resource_type(mut self, input: crate::types::AggregatorFilterResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object to filter the configuration recorders based on the resource types in scope for recording.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::AggregatorFilterResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>An object to filter the configuration recorders based on the resource types in scope for recording.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::AggregatorFilterResourceType> {
        &self.resource_type
    }
    /// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
    pub fn service_principal(mut self, input: crate::types::AggregatorFilterServicePrincipal) -> Self {
        self.service_principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
    pub fn set_service_principal(mut self, input: ::std::option::Option<crate::types::AggregatorFilterServicePrincipal>) -> Self {
        self.service_principal = input;
        self
    }
    /// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
    pub fn get_service_principal(&self) -> &::std::option::Option<crate::types::AggregatorFilterServicePrincipal> {
        &self.service_principal
    }
    /// Consumes the builder and constructs a [`AggregatorFilters`](crate::types::AggregatorFilters).
    pub fn build(self) -> crate::types::AggregatorFilters {
        crate::types::AggregatorFilters {
            resource_type: self.resource_type,
            service_principal: self.service_principal,
        }
    }
}
