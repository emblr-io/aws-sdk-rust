// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Statistics about a label used in a dataset. For more information, see <code>DatasetLabelDescription</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DatasetLabelStats {
    /// <p>The total number of images that use the label.</p>
    pub entry_count: ::std::option::Option<i32>,
    /// <p>The total number of images that have the label assigned to a bounding box.</p>
    pub bounding_box_count: ::std::option::Option<i32>,
}
impl DatasetLabelStats {
    /// <p>The total number of images that use the label.</p>
    pub fn entry_count(&self) -> ::std::option::Option<i32> {
        self.entry_count
    }
    /// <p>The total number of images that have the label assigned to a bounding box.</p>
    pub fn bounding_box_count(&self) -> ::std::option::Option<i32> {
        self.bounding_box_count
    }
}
impl DatasetLabelStats {
    /// Creates a new builder-style object to manufacture [`DatasetLabelStats`](crate::types::DatasetLabelStats).
    pub fn builder() -> crate::types::builders::DatasetLabelStatsBuilder {
        crate::types::builders::DatasetLabelStatsBuilder::default()
    }
}

/// A builder for [`DatasetLabelStats`](crate::types::DatasetLabelStats).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatasetLabelStatsBuilder {
    pub(crate) entry_count: ::std::option::Option<i32>,
    pub(crate) bounding_box_count: ::std::option::Option<i32>,
}
impl DatasetLabelStatsBuilder {
    /// <p>The total number of images that use the label.</p>
    pub fn entry_count(mut self, input: i32) -> Self {
        self.entry_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of images that use the label.</p>
    pub fn set_entry_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.entry_count = input;
        self
    }
    /// <p>The total number of images that use the label.</p>
    pub fn get_entry_count(&self) -> &::std::option::Option<i32> {
        &self.entry_count
    }
    /// <p>The total number of images that have the label assigned to a bounding box.</p>
    pub fn bounding_box_count(mut self, input: i32) -> Self {
        self.bounding_box_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of images that have the label assigned to a bounding box.</p>
    pub fn set_bounding_box_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.bounding_box_count = input;
        self
    }
    /// <p>The total number of images that have the label assigned to a bounding box.</p>
    pub fn get_bounding_box_count(&self) -> &::std::option::Option<i32> {
        &self.bounding_box_count
    }
    /// Consumes the builder and constructs a [`DatasetLabelStats`](crate::types::DatasetLabelStats).
    pub fn build(self) -> crate::types::DatasetLabelStats {
        crate::types::DatasetLabelStats {
            entry_count: self.entry_count,
            bounding_box_count: self.bounding_box_count,
        }
    }
}
