// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This contains arrays of objects, which may include CreationTimes time condition objects, FilePaths string objects, LastModificationTimes time condition objects,</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EbsItemFilter {
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one file path is included, the results will return only items that match the file path.</p>
    /// <p>If more than one file path is included, the results will return all items that match any of the file paths.</p>
    pub file_paths: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub sizes: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub creation_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub last_modification_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
}
impl EbsItemFilter {
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one file path is included, the results will return only items that match the file path.</p>
    /// <p>If more than one file path is included, the results will return all items that match any of the file paths.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.file_paths.is_none()`.
    pub fn file_paths(&self) -> &[crate::types::StringCondition] {
        self.file_paths.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sizes.is_none()`.
    pub fn sizes(&self) -> &[crate::types::LongCondition] {
        self.sizes.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.creation_times.is_none()`.
    pub fn creation_times(&self) -> &[crate::types::TimeCondition] {
        self.creation_times.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.last_modification_times.is_none()`.
    pub fn last_modification_times(&self) -> &[crate::types::TimeCondition] {
        self.last_modification_times.as_deref().unwrap_or_default()
    }
}
impl EbsItemFilter {
    /// Creates a new builder-style object to manufacture [`EbsItemFilter`](crate::types::EbsItemFilter).
    pub fn builder() -> crate::types::builders::EbsItemFilterBuilder {
        crate::types::builders::EbsItemFilterBuilder::default()
    }
}

/// A builder for [`EbsItemFilter`](crate::types::EbsItemFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EbsItemFilterBuilder {
    pub(crate) file_paths: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    pub(crate) sizes: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>,
    pub(crate) creation_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
    pub(crate) last_modification_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
}
impl EbsItemFilterBuilder {
    /// Appends an item to `file_paths`.
    ///
    /// To override the contents of this collection use [`set_file_paths`](Self::set_file_paths).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one file path is included, the results will return only items that match the file path.</p>
    /// <p>If more than one file path is included, the results will return all items that match any of the file paths.</p>
    pub fn file_paths(mut self, input: crate::types::StringCondition) -> Self {
        let mut v = self.file_paths.unwrap_or_default();
        v.push(input);
        self.file_paths = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one file path is included, the results will return only items that match the file path.</p>
    /// <p>If more than one file path is included, the results will return all items that match any of the file paths.</p>
    pub fn set_file_paths(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>) -> Self {
        self.file_paths = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one file path is included, the results will return only items that match the file path.</p>
    /// <p>If more than one file path is included, the results will return all items that match any of the file paths.</p>
    pub fn get_file_paths(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StringCondition>> {
        &self.file_paths
    }
    /// Appends an item to `sizes`.
    ///
    /// To override the contents of this collection use [`set_sizes`](Self::set_sizes).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn sizes(mut self, input: crate::types::LongCondition) -> Self {
        let mut v = self.sizes.unwrap_or_default();
        v.push(input);
        self.sizes = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn set_sizes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>) -> Self {
        self.sizes = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn get_sizes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LongCondition>> {
        &self.sizes
    }
    /// Appends an item to `creation_times`.
    ///
    /// To override the contents of this collection use [`set_creation_times`](Self::set_creation_times).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn creation_times(mut self, input: crate::types::TimeCondition) -> Self {
        let mut v = self.creation_times.unwrap_or_default();
        v.push(input);
        self.creation_times = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn set_creation_times(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>) -> Self {
        self.creation_times = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn get_creation_times(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>> {
        &self.creation_times
    }
    /// Appends an item to `last_modification_times`.
    ///
    /// To override the contents of this collection use [`set_last_modification_times`](Self::set_last_modification_times).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn last_modification_times(mut self, input: crate::types::TimeCondition) -> Self {
        let mut v = self.last_modification_times.unwrap_or_default();
        v.push(input);
        self.last_modification_times = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn set_last_modification_times(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>) -> Self {
        self.last_modification_times = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one is included, the results will return only items that match.</p>
    /// <p>If more than one is included, the results will return all items that match any of the included values.</p>
    pub fn get_last_modification_times(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>> {
        &self.last_modification_times
    }
    /// Consumes the builder and constructs a [`EbsItemFilter`](crate::types::EbsItemFilter).
    pub fn build(self) -> crate::types::EbsItemFilter {
        crate::types::EbsItemFilter {
            file_paths: self.file_paths,
            sizes: self.sizes,
            creation_times: self.creation_times,
            last_modification_times: self.last_modification_times,
        }
    }
}
