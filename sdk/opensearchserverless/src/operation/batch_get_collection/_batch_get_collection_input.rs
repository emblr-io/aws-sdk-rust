// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetCollectionInput {
    /// <p>A list of collection IDs. You can't provide names and IDs in the same request. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of collection names. You can't provide names and IDs in the same request.</p>
    pub names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetCollectionInput {
    /// <p>A list of collection IDs. You can't provide names and IDs in the same request. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ids.is_none()`.
    pub fn ids(&self) -> &[::std::string::String] {
        self.ids.as_deref().unwrap_or_default()
    }
    /// <p>A list of collection names. You can't provide names and IDs in the same request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.names.is_none()`.
    pub fn names(&self) -> &[::std::string::String] {
        self.names.as_deref().unwrap_or_default()
    }
}
impl BatchGetCollectionInput {
    /// Creates a new builder-style object to manufacture [`BatchGetCollectionInput`](crate::operation::batch_get_collection::BatchGetCollectionInput).
    pub fn builder() -> crate::operation::batch_get_collection::builders::BatchGetCollectionInputBuilder {
        crate::operation::batch_get_collection::builders::BatchGetCollectionInputBuilder::default()
    }
}

/// A builder for [`BatchGetCollectionInput`](crate::operation::batch_get_collection::BatchGetCollectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetCollectionInputBuilder {
    pub(crate) ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetCollectionInputBuilder {
    /// Appends an item to `ids`.
    ///
    /// To override the contents of this collection use [`set_ids`](Self::set_ids).
    ///
    /// <p>A list of collection IDs. You can't provide names and IDs in the same request. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ids.unwrap_or_default();
        v.push(input.into());
        self.ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of collection IDs. You can't provide names and IDs in the same request. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ids = input;
        self
    }
    /// <p>A list of collection IDs. You can't provide names and IDs in the same request. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn get_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ids
    }
    /// Appends an item to `names`.
    ///
    /// To override the contents of this collection use [`set_names`](Self::set_names).
    ///
    /// <p>A list of collection names. You can't provide names and IDs in the same request.</p>
    pub fn names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.names.unwrap_or_default();
        v.push(input.into());
        self.names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of collection names. You can't provide names and IDs in the same request.</p>
    pub fn set_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.names = input;
        self
    }
    /// <p>A list of collection names. You can't provide names and IDs in the same request.</p>
    pub fn get_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.names
    }
    /// Consumes the builder and constructs a [`BatchGetCollectionInput`](crate::operation::batch_get_collection::BatchGetCollectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_get_collection::BatchGetCollectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::batch_get_collection::BatchGetCollectionInput {
            ids: self.ids,
            names: self.names,
        })
    }
}
