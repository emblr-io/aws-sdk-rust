// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information used to sort workflows in the returned list.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowSortCriteria {}
impl WorkflowSortCriteria {
    /// Creates a new builder-style object to manufacture [`WorkflowSortCriteria`](crate::types::WorkflowSortCriteria).
    pub fn builder() -> crate::types::builders::WorkflowSortCriteriaBuilder {
        crate::types::builders::WorkflowSortCriteriaBuilder::default()
    }
}

/// A builder for [`WorkflowSortCriteria`](crate::types::WorkflowSortCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowSortCriteriaBuilder {}
impl WorkflowSortCriteriaBuilder {
    /// Consumes the builder and constructs a [`WorkflowSortCriteria`](crate::types::WorkflowSortCriteria).
    pub fn build(self) -> crate::types::WorkflowSortCriteria {
        crate::types::WorkflowSortCriteria {}
    }
}
