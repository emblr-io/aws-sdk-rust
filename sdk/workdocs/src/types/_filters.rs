// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters results based on entity metadata.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Filters {
    /// <p>Filters by the locale of the content or comment.</p>
    pub text_locales: ::std::option::Option<::std::vec::Vec<crate::types::LanguageCodeType>>,
    /// <p>Filters by content category.</p>
    pub content_categories: ::std::option::Option<::std::vec::Vec<crate::types::ContentCategoryType>>,
    /// <p>Filters based on entity type.</p>
    pub resource_types: ::std::option::Option<::std::vec::Vec<crate::types::SearchResourceType>>,
    /// <p>Filter by labels using exact match.</p>
    pub labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filter based on UserIds or GroupIds.</p>
    pub principals: ::std::option::Option<::std::vec::Vec<crate::types::SearchPrincipalType>>,
    /// <p>Filter based on resource’s path.</p>
    pub ancestor_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filter based on file groupings.</p>
    pub search_collection_types: ::std::option::Option<::std::vec::Vec<crate::types::SearchCollectionType>>,
    /// <p>Filter based on size (in bytes).</p>
    pub size_range: ::std::option::Option<crate::types::LongRangeType>,
    /// <p>Filter based on resource’s creation timestamp.</p>
    pub created_range: ::std::option::Option<crate::types::DateRangeType>,
    /// <p>Filter based on resource’s modified timestamp.</p>
    pub modified_range: ::std::option::Option<crate::types::DateRangeType>,
}
impl Filters {
    /// <p>Filters by the locale of the content or comment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.text_locales.is_none()`.
    pub fn text_locales(&self) -> &[crate::types::LanguageCodeType] {
        self.text_locales.as_deref().unwrap_or_default()
    }
    /// <p>Filters by content category.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.content_categories.is_none()`.
    pub fn content_categories(&self) -> &[crate::types::ContentCategoryType] {
        self.content_categories.as_deref().unwrap_or_default()
    }
    /// <p>Filters based on entity type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_types.is_none()`.
    pub fn resource_types(&self) -> &[crate::types::SearchResourceType] {
        self.resource_types.as_deref().unwrap_or_default()
    }
    /// <p>Filter by labels using exact match.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.labels.is_none()`.
    pub fn labels(&self) -> &[::std::string::String] {
        self.labels.as_deref().unwrap_or_default()
    }
    /// <p>Filter based on UserIds or GroupIds.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.principals.is_none()`.
    pub fn principals(&self) -> &[crate::types::SearchPrincipalType] {
        self.principals.as_deref().unwrap_or_default()
    }
    /// <p>Filter based on resource’s path.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ancestor_ids.is_none()`.
    pub fn ancestor_ids(&self) -> &[::std::string::String] {
        self.ancestor_ids.as_deref().unwrap_or_default()
    }
    /// <p>Filter based on file groupings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.search_collection_types.is_none()`.
    pub fn search_collection_types(&self) -> &[crate::types::SearchCollectionType] {
        self.search_collection_types.as_deref().unwrap_or_default()
    }
    /// <p>Filter based on size (in bytes).</p>
    pub fn size_range(&self) -> ::std::option::Option<&crate::types::LongRangeType> {
        self.size_range.as_ref()
    }
    /// <p>Filter based on resource’s creation timestamp.</p>
    pub fn created_range(&self) -> ::std::option::Option<&crate::types::DateRangeType> {
        self.created_range.as_ref()
    }
    /// <p>Filter based on resource’s modified timestamp.</p>
    pub fn modified_range(&self) -> ::std::option::Option<&crate::types::DateRangeType> {
        self.modified_range.as_ref()
    }
}
impl Filters {
    /// Creates a new builder-style object to manufacture [`Filters`](crate::types::Filters).
    pub fn builder() -> crate::types::builders::FiltersBuilder {
        crate::types::builders::FiltersBuilder::default()
    }
}

/// A builder for [`Filters`](crate::types::Filters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FiltersBuilder {
    pub(crate) text_locales: ::std::option::Option<::std::vec::Vec<crate::types::LanguageCodeType>>,
    pub(crate) content_categories: ::std::option::Option<::std::vec::Vec<crate::types::ContentCategoryType>>,
    pub(crate) resource_types: ::std::option::Option<::std::vec::Vec<crate::types::SearchResourceType>>,
    pub(crate) labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) principals: ::std::option::Option<::std::vec::Vec<crate::types::SearchPrincipalType>>,
    pub(crate) ancestor_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) search_collection_types: ::std::option::Option<::std::vec::Vec<crate::types::SearchCollectionType>>,
    pub(crate) size_range: ::std::option::Option<crate::types::LongRangeType>,
    pub(crate) created_range: ::std::option::Option<crate::types::DateRangeType>,
    pub(crate) modified_range: ::std::option::Option<crate::types::DateRangeType>,
}
impl FiltersBuilder {
    /// Appends an item to `text_locales`.
    ///
    /// To override the contents of this collection use [`set_text_locales`](Self::set_text_locales).
    ///
    /// <p>Filters by the locale of the content or comment.</p>
    pub fn text_locales(mut self, input: crate::types::LanguageCodeType) -> Self {
        let mut v = self.text_locales.unwrap_or_default();
        v.push(input);
        self.text_locales = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters by the locale of the content or comment.</p>
    pub fn set_text_locales(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LanguageCodeType>>) -> Self {
        self.text_locales = input;
        self
    }
    /// <p>Filters by the locale of the content or comment.</p>
    pub fn get_text_locales(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LanguageCodeType>> {
        &self.text_locales
    }
    /// Appends an item to `content_categories`.
    ///
    /// To override the contents of this collection use [`set_content_categories`](Self::set_content_categories).
    ///
    /// <p>Filters by content category.</p>
    pub fn content_categories(mut self, input: crate::types::ContentCategoryType) -> Self {
        let mut v = self.content_categories.unwrap_or_default();
        v.push(input);
        self.content_categories = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters by content category.</p>
    pub fn set_content_categories(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContentCategoryType>>) -> Self {
        self.content_categories = input;
        self
    }
    /// <p>Filters by content category.</p>
    pub fn get_content_categories(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContentCategoryType>> {
        &self.content_categories
    }
    /// Appends an item to `resource_types`.
    ///
    /// To override the contents of this collection use [`set_resource_types`](Self::set_resource_types).
    ///
    /// <p>Filters based on entity type.</p>
    pub fn resource_types(mut self, input: crate::types::SearchResourceType) -> Self {
        let mut v = self.resource_types.unwrap_or_default();
        v.push(input);
        self.resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters based on entity type.</p>
    pub fn set_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SearchResourceType>>) -> Self {
        self.resource_types = input;
        self
    }
    /// <p>Filters based on entity type.</p>
    pub fn get_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SearchResourceType>> {
        &self.resource_types
    }
    /// Appends an item to `labels`.
    ///
    /// To override the contents of this collection use [`set_labels`](Self::set_labels).
    ///
    /// <p>Filter by labels using exact match.</p>
    pub fn labels(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.labels.unwrap_or_default();
        v.push(input.into());
        self.labels = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter by labels using exact match.</p>
    pub fn set_labels(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.labels = input;
        self
    }
    /// <p>Filter by labels using exact match.</p>
    pub fn get_labels(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.labels
    }
    /// Appends an item to `principals`.
    ///
    /// To override the contents of this collection use [`set_principals`](Self::set_principals).
    ///
    /// <p>Filter based on UserIds or GroupIds.</p>
    pub fn principals(mut self, input: crate::types::SearchPrincipalType) -> Self {
        let mut v = self.principals.unwrap_or_default();
        v.push(input);
        self.principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter based on UserIds or GroupIds.</p>
    pub fn set_principals(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SearchPrincipalType>>) -> Self {
        self.principals = input;
        self
    }
    /// <p>Filter based on UserIds or GroupIds.</p>
    pub fn get_principals(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SearchPrincipalType>> {
        &self.principals
    }
    /// Appends an item to `ancestor_ids`.
    ///
    /// To override the contents of this collection use [`set_ancestor_ids`](Self::set_ancestor_ids).
    ///
    /// <p>Filter based on resource’s path.</p>
    pub fn ancestor_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ancestor_ids.unwrap_or_default();
        v.push(input.into());
        self.ancestor_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter based on resource’s path.</p>
    pub fn set_ancestor_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ancestor_ids = input;
        self
    }
    /// <p>Filter based on resource’s path.</p>
    pub fn get_ancestor_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ancestor_ids
    }
    /// Appends an item to `search_collection_types`.
    ///
    /// To override the contents of this collection use [`set_search_collection_types`](Self::set_search_collection_types).
    ///
    /// <p>Filter based on file groupings.</p>
    pub fn search_collection_types(mut self, input: crate::types::SearchCollectionType) -> Self {
        let mut v = self.search_collection_types.unwrap_or_default();
        v.push(input);
        self.search_collection_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filter based on file groupings.</p>
    pub fn set_search_collection_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SearchCollectionType>>) -> Self {
        self.search_collection_types = input;
        self
    }
    /// <p>Filter based on file groupings.</p>
    pub fn get_search_collection_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SearchCollectionType>> {
        &self.search_collection_types
    }
    /// <p>Filter based on size (in bytes).</p>
    pub fn size_range(mut self, input: crate::types::LongRangeType) -> Self {
        self.size_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter based on size (in bytes).</p>
    pub fn set_size_range(mut self, input: ::std::option::Option<crate::types::LongRangeType>) -> Self {
        self.size_range = input;
        self
    }
    /// <p>Filter based on size (in bytes).</p>
    pub fn get_size_range(&self) -> &::std::option::Option<crate::types::LongRangeType> {
        &self.size_range
    }
    /// <p>Filter based on resource’s creation timestamp.</p>
    pub fn created_range(mut self, input: crate::types::DateRangeType) -> Self {
        self.created_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter based on resource’s creation timestamp.</p>
    pub fn set_created_range(mut self, input: ::std::option::Option<crate::types::DateRangeType>) -> Self {
        self.created_range = input;
        self
    }
    /// <p>Filter based on resource’s creation timestamp.</p>
    pub fn get_created_range(&self) -> &::std::option::Option<crate::types::DateRangeType> {
        &self.created_range
    }
    /// <p>Filter based on resource’s modified timestamp.</p>
    pub fn modified_range(mut self, input: crate::types::DateRangeType) -> Self {
        self.modified_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter based on resource’s modified timestamp.</p>
    pub fn set_modified_range(mut self, input: ::std::option::Option<crate::types::DateRangeType>) -> Self {
        self.modified_range = input;
        self
    }
    /// <p>Filter based on resource’s modified timestamp.</p>
    pub fn get_modified_range(&self) -> &::std::option::Option<crate::types::DateRangeType> {
        &self.modified_range
    }
    /// Consumes the builder and constructs a [`Filters`](crate::types::Filters).
    pub fn build(self) -> crate::types::Filters {
        crate::types::Filters {
            text_locales: self.text_locales,
            content_categories: self.content_categories,
            resource_types: self.resource_types,
            labels: self.labels,
            principals: self.principals,
            ancestor_ids: self.ancestor_ids,
            search_collection_types: self.search_collection_types,
            size_range: self.size_range,
            created_range: self.created_range,
            modified_range: self.modified_range,
        }
    }
}
