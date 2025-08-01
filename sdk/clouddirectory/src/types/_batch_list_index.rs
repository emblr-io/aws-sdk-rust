// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Lists objects attached to the specified index inside a <code>BatchRead</code> operation. For more information, see <code>ListIndex</code> and <code>BatchReadRequest$Operations</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchListIndex {
    /// <p>Specifies the ranges of indexed values that you want to query.</p>
    pub ranges_on_indexed_values: ::std::option::Option<::std::vec::Vec<crate::types::ObjectAttributeRange>>,
    /// <p>The reference to the index to list.</p>
    pub index_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>The maximum number of results to retrieve.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl BatchListIndex {
    /// <p>Specifies the ranges of indexed values that you want to query.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ranges_on_indexed_values.is_none()`.
    pub fn ranges_on_indexed_values(&self) -> &[crate::types::ObjectAttributeRange] {
        self.ranges_on_indexed_values.as_deref().unwrap_or_default()
    }
    /// <p>The reference to the index to list.</p>
    pub fn index_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.index_reference.as_ref()
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl BatchListIndex {
    /// Creates a new builder-style object to manufacture [`BatchListIndex`](crate::types::BatchListIndex).
    pub fn builder() -> crate::types::builders::BatchListIndexBuilder {
        crate::types::builders::BatchListIndexBuilder::default()
    }
}

/// A builder for [`BatchListIndex`](crate::types::BatchListIndex).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchListIndexBuilder {
    pub(crate) ranges_on_indexed_values: ::std::option::Option<::std::vec::Vec<crate::types::ObjectAttributeRange>>,
    pub(crate) index_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl BatchListIndexBuilder {
    /// Appends an item to `ranges_on_indexed_values`.
    ///
    /// To override the contents of this collection use [`set_ranges_on_indexed_values`](Self::set_ranges_on_indexed_values).
    ///
    /// <p>Specifies the ranges of indexed values that you want to query.</p>
    pub fn ranges_on_indexed_values(mut self, input: crate::types::ObjectAttributeRange) -> Self {
        let mut v = self.ranges_on_indexed_values.unwrap_or_default();
        v.push(input);
        self.ranges_on_indexed_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the ranges of indexed values that you want to query.</p>
    pub fn set_ranges_on_indexed_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ObjectAttributeRange>>) -> Self {
        self.ranges_on_indexed_values = input;
        self
    }
    /// <p>Specifies the ranges of indexed values that you want to query.</p>
    pub fn get_ranges_on_indexed_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ObjectAttributeRange>> {
        &self.ranges_on_indexed_values
    }
    /// <p>The reference to the index to list.</p>
    /// This field is required.
    pub fn index_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.index_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reference to the index to list.</p>
    pub fn set_index_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.index_reference = input;
        self
    }
    /// <p>The reference to the index to list.</p>
    pub fn get_index_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.index_reference
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`BatchListIndex`](crate::types::BatchListIndex).
    pub fn build(self) -> crate::types::BatchListIndex {
        crate::types::BatchListIndex {
            ranges_on_indexed_values: self.ranges_on_indexed_values,
            index_reference: self.index_reference,
            max_results: self.max_results,
            next_token: self.next_token,
        }
    }
}
