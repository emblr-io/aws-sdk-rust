// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a field to sort by and a sort order.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SortCriterion {
    /// <p>The name of the field on which to sort.</p>
    pub field_name: ::std::option::Option<::std::string::String>,
    /// <p>An ascending or descending sort.</p>
    pub sort: ::std::option::Option<crate::types::Sort>,
}
impl SortCriterion {
    /// <p>The name of the field on which to sort.</p>
    pub fn field_name(&self) -> ::std::option::Option<&str> {
        self.field_name.as_deref()
    }
    /// <p>An ascending or descending sort.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::Sort> {
        self.sort.as_ref()
    }
}
impl SortCriterion {
    /// Creates a new builder-style object to manufacture [`SortCriterion`](crate::types::SortCriterion).
    pub fn builder() -> crate::types::builders::SortCriterionBuilder {
        crate::types::builders::SortCriterionBuilder::default()
    }
}

/// A builder for [`SortCriterion`](crate::types::SortCriterion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SortCriterionBuilder {
    pub(crate) field_name: ::std::option::Option<::std::string::String>,
    pub(crate) sort: ::std::option::Option<crate::types::Sort>,
}
impl SortCriterionBuilder {
    /// <p>The name of the field on which to sort.</p>
    pub fn field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field on which to sort.</p>
    pub fn set_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field_name = input;
        self
    }
    /// <p>The name of the field on which to sort.</p>
    pub fn get_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.field_name
    }
    /// <p>An ascending or descending sort.</p>
    pub fn sort(mut self, input: crate::types::Sort) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>An ascending or descending sort.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::Sort>) -> Self {
        self.sort = input;
        self
    }
    /// <p>An ascending or descending sort.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::Sort> {
        &self.sort
    }
    /// Consumes the builder and constructs a [`SortCriterion`](crate::types::SortCriterion).
    pub fn build(self) -> crate::types::SortCriterion {
        crate::types::SortCriterion {
            field_name: self.field_name,
            sort: self.sort,
        }
    }
}
