// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Enables filtering of security findings based on string field values in OCSF.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OcsfStringFilter {
    /// <p>The name of the field.</p>
    pub field_name: ::std::option::Option<crate::types::OcsfStringField>,
    /// <p>A string filter for filtering Security Hub findings.</p>
    pub filter: ::std::option::Option<crate::types::StringFilter>,
}
impl OcsfStringFilter {
    /// <p>The name of the field.</p>
    pub fn field_name(&self) -> ::std::option::Option<&crate::types::OcsfStringField> {
        self.field_name.as_ref()
    }
    /// <p>A string filter for filtering Security Hub findings.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::StringFilter> {
        self.filter.as_ref()
    }
}
impl OcsfStringFilter {
    /// Creates a new builder-style object to manufacture [`OcsfStringFilter`](crate::types::OcsfStringFilter).
    pub fn builder() -> crate::types::builders::OcsfStringFilterBuilder {
        crate::types::builders::OcsfStringFilterBuilder::default()
    }
}

/// A builder for [`OcsfStringFilter`](crate::types::OcsfStringFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OcsfStringFilterBuilder {
    pub(crate) field_name: ::std::option::Option<crate::types::OcsfStringField>,
    pub(crate) filter: ::std::option::Option<crate::types::StringFilter>,
}
impl OcsfStringFilterBuilder {
    /// <p>The name of the field.</p>
    pub fn field_name(mut self, input: crate::types::OcsfStringField) -> Self {
        self.field_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the field.</p>
    pub fn set_field_name(mut self, input: ::std::option::Option<crate::types::OcsfStringField>) -> Self {
        self.field_name = input;
        self
    }
    /// <p>The name of the field.</p>
    pub fn get_field_name(&self) -> &::std::option::Option<crate::types::OcsfStringField> {
        &self.field_name
    }
    /// <p>A string filter for filtering Security Hub findings.</p>
    pub fn filter(mut self, input: crate::types::StringFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>A string filter for filtering Security Hub findings.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::StringFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>A string filter for filtering Security Hub findings.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::StringFilter> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`OcsfStringFilter`](crate::types::OcsfStringFilter).
    pub fn build(self) -> crate::types::OcsfStringFilter {
        crate::types::OcsfStringFilter {
            field_name: self.field_name,
            filter: self.filter,
        }
    }
}
