// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Analysis results for one of the documents in the batch.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDetectTargetedSentimentItemResult {
    /// <p>The zero-based index of this result in the input list.</p>
    pub index: ::std::option::Option<i32>,
    /// <p>An array of targeted sentiment entities.</p>
    pub entities: ::std::option::Option<::std::vec::Vec<crate::types::TargetedSentimentEntity>>,
}
impl BatchDetectTargetedSentimentItemResult {
    /// <p>The zero-based index of this result in the input list.</p>
    pub fn index(&self) -> ::std::option::Option<i32> {
        self.index
    }
    /// <p>An array of targeted sentiment entities.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.entities.is_none()`.
    pub fn entities(&self) -> &[crate::types::TargetedSentimentEntity] {
        self.entities.as_deref().unwrap_or_default()
    }
}
impl BatchDetectTargetedSentimentItemResult {
    /// Creates a new builder-style object to manufacture [`BatchDetectTargetedSentimentItemResult`](crate::types::BatchDetectTargetedSentimentItemResult).
    pub fn builder() -> crate::types::builders::BatchDetectTargetedSentimentItemResultBuilder {
        crate::types::builders::BatchDetectTargetedSentimentItemResultBuilder::default()
    }
}

/// A builder for [`BatchDetectTargetedSentimentItemResult`](crate::types::BatchDetectTargetedSentimentItemResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDetectTargetedSentimentItemResultBuilder {
    pub(crate) index: ::std::option::Option<i32>,
    pub(crate) entities: ::std::option::Option<::std::vec::Vec<crate::types::TargetedSentimentEntity>>,
}
impl BatchDetectTargetedSentimentItemResultBuilder {
    /// <p>The zero-based index of this result in the input list.</p>
    pub fn index(mut self, input: i32) -> Self {
        self.index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The zero-based index of this result in the input list.</p>
    pub fn set_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.index = input;
        self
    }
    /// <p>The zero-based index of this result in the input list.</p>
    pub fn get_index(&self) -> &::std::option::Option<i32> {
        &self.index
    }
    /// Appends an item to `entities`.
    ///
    /// To override the contents of this collection use [`set_entities`](Self::set_entities).
    ///
    /// <p>An array of targeted sentiment entities.</p>
    pub fn entities(mut self, input: crate::types::TargetedSentimentEntity) -> Self {
        let mut v = self.entities.unwrap_or_default();
        v.push(input);
        self.entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of targeted sentiment entities.</p>
    pub fn set_entities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TargetedSentimentEntity>>) -> Self {
        self.entities = input;
        self
    }
    /// <p>An array of targeted sentiment entities.</p>
    pub fn get_entities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TargetedSentimentEntity>> {
        &self.entities
    }
    /// Consumes the builder and constructs a [`BatchDetectTargetedSentimentItemResult`](crate::types::BatchDetectTargetedSentimentItemResult).
    pub fn build(self) -> crate::types::BatchDetectTargetedSentimentItemResult {
        crate::types::BatchDetectTargetedSentimentItemResult {
            index: self.index,
            entities: self.entities,
        }
    }
}
