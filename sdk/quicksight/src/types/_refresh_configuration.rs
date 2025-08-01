// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The refresh configuration of a dataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RefreshConfiguration {
    /// <p>The incremental refresh for the dataset.</p>
    pub incremental_refresh: ::std::option::Option<crate::types::IncrementalRefresh>,
}
impl RefreshConfiguration {
    /// <p>The incremental refresh for the dataset.</p>
    pub fn incremental_refresh(&self) -> ::std::option::Option<&crate::types::IncrementalRefresh> {
        self.incremental_refresh.as_ref()
    }
}
impl RefreshConfiguration {
    /// Creates a new builder-style object to manufacture [`RefreshConfiguration`](crate::types::RefreshConfiguration).
    pub fn builder() -> crate::types::builders::RefreshConfigurationBuilder {
        crate::types::builders::RefreshConfigurationBuilder::default()
    }
}

/// A builder for [`RefreshConfiguration`](crate::types::RefreshConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RefreshConfigurationBuilder {
    pub(crate) incremental_refresh: ::std::option::Option<crate::types::IncrementalRefresh>,
}
impl RefreshConfigurationBuilder {
    /// <p>The incremental refresh for the dataset.</p>
    /// This field is required.
    pub fn incremental_refresh(mut self, input: crate::types::IncrementalRefresh) -> Self {
        self.incremental_refresh = ::std::option::Option::Some(input);
        self
    }
    /// <p>The incremental refresh for the dataset.</p>
    pub fn set_incremental_refresh(mut self, input: ::std::option::Option<crate::types::IncrementalRefresh>) -> Self {
        self.incremental_refresh = input;
        self
    }
    /// <p>The incremental refresh for the dataset.</p>
    pub fn get_incremental_refresh(&self) -> &::std::option::Option<crate::types::IncrementalRefresh> {
        &self.incremental_refresh
    }
    /// Consumes the builder and constructs a [`RefreshConfiguration`](crate::types::RefreshConfiguration).
    pub fn build(self) -> crate::types::RefreshConfiguration {
        crate::types::RefreshConfiguration {
            incremental_refresh: self.incremental_refresh,
        }
    }
}
