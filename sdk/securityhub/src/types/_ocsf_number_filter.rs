// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Enables filtering of security findings based on numerical field values in OCSF.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OcsfNumberFilter {
    /// <p>The name of the field.</p>
    pub field_name: ::std::option::Option<crate::types::OcsfNumberField>,
    /// <p>A number filter for querying findings.</p>
    pub filter: ::std::option::Option<crate::types::NumberFilter>,
}
impl OcsfNumberFilter {
    /// <p>The name of the field.</p>
    pub fn field_name(&self) -> ::std::option::Option<&crate::types::OcsfNumberField> {
        self.field_name.as_ref()
    }
    /// <p>A number filter for querying findings.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::NumberFilter> {
        self.filter.as_ref()
    }
}
impl OcsfNumberFilter {
    /// Creates a new builder-style object to manufacture [`OcsfNumberFilter`](crate::types::OcsfNumberFilter).
    pub fn builder() -> crate::types::builders::OcsfNumberFilterBuilder {
        crate::types::builders::OcsfNumberFilterBuilder::default()
    }
}

/// A builder for [`OcsfNumberFilter`](crate::types::OcsfNumberFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OcsfNumberFilterBuilder {
    pub(crate) field_name: ::std::option::Option<crate::types::OcsfNumberField>,
    pub(crate) filter: ::std::option::Option<crate::types::NumberFilter>,
}
impl OcsfNumberFilterBuilder {
    /// <p>The name of the field.</p>
    pub fn field_name(mut self, input: crate::types::OcsfNumberField) -> Self {
        self.field_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the field.</p>
    pub fn set_field_name(mut self, input: ::std::option::Option<crate::types::OcsfNumberField>) -> Self {
        self.field_name = input;
        self
    }
    /// <p>The name of the field.</p>
    pub fn get_field_name(&self) -> &::std::option::Option<crate::types::OcsfNumberField> {
        &self.field_name
    }
    /// <p>A number filter for querying findings.</p>
    pub fn filter(mut self, input: crate::types::NumberFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>A number filter for querying findings.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::NumberFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>A number filter for querying findings.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::NumberFilter> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`OcsfNumberFilter`](crate::types::OcsfNumberFilter).
    pub fn build(self) -> crate::types::OcsfNumberFilter {
        crate::types::OcsfNumberFilter {
            field_name: self.field_name,
            filter: self.filter,
        }
    }
}
