// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object to filter service-linked configuration recorders in an aggregator based on the linked Amazon Web Services service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AggregatorFilterServicePrincipal {
    /// <p>The type of service principal filter to apply. <code>INCLUDE</code> specifies that the list of service principals in the <code>Value</code> field will be aggregated and no other service principals will be filtered.</p>
    pub r#type: ::std::option::Option<crate::types::AggregatorFilterType>,
    /// <p>Comma-separated list of service principals for the linked Amazon Web Services services to filter your aggregated service-linked configuration recorders.</p>
    pub value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AggregatorFilterServicePrincipal {
    /// <p>The type of service principal filter to apply. <code>INCLUDE</code> specifies that the list of service principals in the <code>Value</code> field will be aggregated and no other service principals will be filtered.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::AggregatorFilterType> {
        self.r#type.as_ref()
    }
    /// <p>Comma-separated list of service principals for the linked Amazon Web Services services to filter your aggregated service-linked configuration recorders.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value.is_none()`.
    pub fn value(&self) -> &[::std::string::String] {
        self.value.as_deref().unwrap_or_default()
    }
}
impl AggregatorFilterServicePrincipal {
    /// Creates a new builder-style object to manufacture [`AggregatorFilterServicePrincipal`](crate::types::AggregatorFilterServicePrincipal).
    pub fn builder() -> crate::types::builders::AggregatorFilterServicePrincipalBuilder {
        crate::types::builders::AggregatorFilterServicePrincipalBuilder::default()
    }
}

/// A builder for [`AggregatorFilterServicePrincipal`](crate::types::AggregatorFilterServicePrincipal).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AggregatorFilterServicePrincipalBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::AggregatorFilterType>,
    pub(crate) value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AggregatorFilterServicePrincipalBuilder {
    /// <p>The type of service principal filter to apply. <code>INCLUDE</code> specifies that the list of service principals in the <code>Value</code> field will be aggregated and no other service principals will be filtered.</p>
    pub fn r#type(mut self, input: crate::types::AggregatorFilterType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of service principal filter to apply. <code>INCLUDE</code> specifies that the list of service principals in the <code>Value</code> field will be aggregated and no other service principals will be filtered.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AggregatorFilterType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of service principal filter to apply. <code>INCLUDE</code> specifies that the list of service principals in the <code>Value</code> field will be aggregated and no other service principals will be filtered.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AggregatorFilterType> {
        &self.r#type
    }
    /// Appends an item to `value`.
    ///
    /// To override the contents of this collection use [`set_value`](Self::set_value).
    ///
    /// <p>Comma-separated list of service principals for the linked Amazon Web Services services to filter your aggregated service-linked configuration recorders.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.value.unwrap_or_default();
        v.push(input.into());
        self.value = ::std::option::Option::Some(v);
        self
    }
    /// <p>Comma-separated list of service principals for the linked Amazon Web Services services to filter your aggregated service-linked configuration recorders.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.value = input;
        self
    }
    /// <p>Comma-separated list of service principals for the linked Amazon Web Services services to filter your aggregated service-linked configuration recorders.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.value
    }
    /// Consumes the builder and constructs a [`AggregatorFilterServicePrincipal`](crate::types::AggregatorFilterServicePrincipal).
    pub fn build(self) -> crate::types::AggregatorFilterServicePrincipal {
        crate::types::AggregatorFilterServicePrincipal {
            r#type: self.r#type,
            value: self.value,
        }
    }
}
