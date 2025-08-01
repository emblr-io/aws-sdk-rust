// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the Storage Lens groups to include in the Storage Lens group aggregation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageLensGroupLevel {
    /// <p>Indicates which Storage Lens group ARNs to include or exclude in the Storage Lens group aggregation. If this value is left null, then all Storage Lens groups are selected.</p>
    pub selection_criteria: ::std::option::Option<crate::types::StorageLensGroupLevelSelectionCriteria>,
}
impl StorageLensGroupLevel {
    /// <p>Indicates which Storage Lens group ARNs to include or exclude in the Storage Lens group aggregation. If this value is left null, then all Storage Lens groups are selected.</p>
    pub fn selection_criteria(&self) -> ::std::option::Option<&crate::types::StorageLensGroupLevelSelectionCriteria> {
        self.selection_criteria.as_ref()
    }
}
impl StorageLensGroupLevel {
    /// Creates a new builder-style object to manufacture [`StorageLensGroupLevel`](crate::types::StorageLensGroupLevel).
    pub fn builder() -> crate::types::builders::StorageLensGroupLevelBuilder {
        crate::types::builders::StorageLensGroupLevelBuilder::default()
    }
}

/// A builder for [`StorageLensGroupLevel`](crate::types::StorageLensGroupLevel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageLensGroupLevelBuilder {
    pub(crate) selection_criteria: ::std::option::Option<crate::types::StorageLensGroupLevelSelectionCriteria>,
}
impl StorageLensGroupLevelBuilder {
    /// <p>Indicates which Storage Lens group ARNs to include or exclude in the Storage Lens group aggregation. If this value is left null, then all Storage Lens groups are selected.</p>
    pub fn selection_criteria(mut self, input: crate::types::StorageLensGroupLevelSelectionCriteria) -> Self {
        self.selection_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates which Storage Lens group ARNs to include or exclude in the Storage Lens group aggregation. If this value is left null, then all Storage Lens groups are selected.</p>
    pub fn set_selection_criteria(mut self, input: ::std::option::Option<crate::types::StorageLensGroupLevelSelectionCriteria>) -> Self {
        self.selection_criteria = input;
        self
    }
    /// <p>Indicates which Storage Lens group ARNs to include or exclude in the Storage Lens group aggregation. If this value is left null, then all Storage Lens groups are selected.</p>
    pub fn get_selection_criteria(&self) -> &::std::option::Option<crate::types::StorageLensGroupLevelSelectionCriteria> {
        &self.selection_criteria
    }
    /// Consumes the builder and constructs a [`StorageLensGroupLevel`](crate::types::StorageLensGroupLevel).
    pub fn build(self) -> crate::types::StorageLensGroupLevel {
        crate::types::StorageLensGroupLevel {
            selection_criteria: self.selection_criteria,
        }
    }
}
