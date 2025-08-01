// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This contains arrays of objects, which may include ObjectKeys, Sizes, CreationTimes, VersionIds, and/or Etags.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3ItemFilter {
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub object_keys: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub sizes: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub creation_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub version_ids: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub e_tags: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
}
impl S3ItemFilter {
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.object_keys.is_none()`.
    pub fn object_keys(&self) -> &[crate::types::StringCondition] {
        self.object_keys.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sizes.is_none()`.
    pub fn sizes(&self) -> &[crate::types::LongCondition] {
        self.sizes.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.creation_times.is_none()`.
    pub fn creation_times(&self) -> &[crate::types::TimeCondition] {
        self.creation_times.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.version_ids.is_none()`.
    pub fn version_ids(&self) -> &[crate::types::StringCondition] {
        self.version_ids.as_deref().unwrap_or_default()
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.e_tags.is_none()`.
    pub fn e_tags(&self) -> &[crate::types::StringCondition] {
        self.e_tags.as_deref().unwrap_or_default()
    }
}
impl S3ItemFilter {
    /// Creates a new builder-style object to manufacture [`S3ItemFilter`](crate::types::S3ItemFilter).
    pub fn builder() -> crate::types::builders::S3ItemFilterBuilder {
        crate::types::builders::S3ItemFilterBuilder::default()
    }
}

/// A builder for [`S3ItemFilter`](crate::types::S3ItemFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ItemFilterBuilder {
    pub(crate) object_keys: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    pub(crate) sizes: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>,
    pub(crate) creation_times: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>,
    pub(crate) version_ids: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
    pub(crate) e_tags: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>,
}
impl S3ItemFilterBuilder {
    /// Appends an item to `object_keys`.
    ///
    /// To override the contents of this collection use [`set_object_keys`](Self::set_object_keys).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn object_keys(mut self, input: crate::types::StringCondition) -> Self {
        let mut v = self.object_keys.unwrap_or_default();
        v.push(input);
        self.object_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn set_object_keys(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>) -> Self {
        self.object_keys = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn get_object_keys(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StringCondition>> {
        &self.object_keys
    }
    /// Appends an item to `sizes`.
    ///
    /// To override the contents of this collection use [`set_sizes`](Self::set_sizes).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn sizes(mut self, input: crate::types::LongCondition) -> Self {
        let mut v = self.sizes.unwrap_or_default();
        v.push(input);
        self.sizes = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn set_sizes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LongCondition>>) -> Self {
        self.sizes = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn get_sizes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LongCondition>> {
        &self.sizes
    }
    /// Appends an item to `creation_times`.
    ///
    /// To override the contents of this collection use [`set_creation_times`](Self::set_creation_times).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn creation_times(mut self, input: crate::types::TimeCondition) -> Self {
        let mut v = self.creation_times.unwrap_or_default();
        v.push(input);
        self.creation_times = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn set_creation_times(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>>) -> Self {
        self.creation_times = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn get_creation_times(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TimeCondition>> {
        &self.creation_times
    }
    /// Appends an item to `version_ids`.
    ///
    /// To override the contents of this collection use [`set_version_ids`](Self::set_version_ids).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn version_ids(mut self, input: crate::types::StringCondition) -> Self {
        let mut v = self.version_ids.unwrap_or_default();
        v.push(input);
        self.version_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn set_version_ids(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>) -> Self {
        self.version_ids = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn get_version_ids(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StringCondition>> {
        &self.version_ids
    }
    /// Appends an item to `e_tags`.
    ///
    /// To override the contents of this collection use [`set_e_tags`](Self::set_e_tags).
    ///
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn e_tags(mut self, input: crate::types::StringCondition) -> Self {
        let mut v = self.e_tags.unwrap_or_default();
        v.push(input);
        self.e_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn set_e_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StringCondition>>) -> Self {
        self.e_tags = input;
        self
    }
    /// <p>You can include 1 to 10 values.</p>
    /// <p>If one value is included, the results will return only items that match the value.</p>
    /// <p>If more than one value is included, the results will return all items that match any of the values.</p>
    pub fn get_e_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StringCondition>> {
        &self.e_tags
    }
    /// Consumes the builder and constructs a [`S3ItemFilter`](crate::types::S3ItemFilter).
    pub fn build(self) -> crate::types::S3ItemFilter {
        crate::types::S3ItemFilter {
            object_keys: self.object_keys,
            sizes: self.sizes,
            creation_times: self.creation_times,
            version_ids: self.version_ids,
            e_tags: self.e_tags,
        }
    }
}
