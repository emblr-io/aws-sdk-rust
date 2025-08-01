// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectEntitiesOutput {
    /// <p>The collection of medical entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub entities: ::std::vec::Vec<crate::types::Entity>,
    /// <p>Attributes extracted from the input text that we were unable to relate to an entity.</p>
    pub unmapped_attributes: ::std::option::Option<::std::vec::Vec<crate::types::UnmappedAttribute>>,
    /// <p>If the result of the previous request to <code>DetectEntities</code> was truncated, include the <code>PaginationToken</code> to fetch the next page of entities.</p>
    pub pagination_token: ::std::option::Option<::std::string::String>,
    /// <p>The version of the model used to analyze the documents. The version number looks like X.X.X. You can use this information to track the model used for a particular batch of documents.</p>
    pub model_version: ::std::string::String,
    _request_id: Option<String>,
}
impl DetectEntitiesOutput {
    /// <p>The collection of medical entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn entities(&self) -> &[crate::types::Entity] {
        use std::ops::Deref;
        self.entities.deref()
    }
    /// <p>Attributes extracted from the input text that we were unable to relate to an entity.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unmapped_attributes.is_none()`.
    pub fn unmapped_attributes(&self) -> &[crate::types::UnmappedAttribute] {
        self.unmapped_attributes.as_deref().unwrap_or_default()
    }
    /// <p>If the result of the previous request to <code>DetectEntities</code> was truncated, include the <code>PaginationToken</code> to fetch the next page of entities.</p>
    pub fn pagination_token(&self) -> ::std::option::Option<&str> {
        self.pagination_token.as_deref()
    }
    /// <p>The version of the model used to analyze the documents. The version number looks like X.X.X. You can use this information to track the model used for a particular batch of documents.</p>
    pub fn model_version(&self) -> &str {
        use std::ops::Deref;
        self.model_version.deref()
    }
}
impl ::aws_types::request_id::RequestId for DetectEntitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DetectEntitiesOutput {
    /// Creates a new builder-style object to manufacture [`DetectEntitiesOutput`](crate::operation::detect_entities::DetectEntitiesOutput).
    pub fn builder() -> crate::operation::detect_entities::builders::DetectEntitiesOutputBuilder {
        crate::operation::detect_entities::builders::DetectEntitiesOutputBuilder::default()
    }
}

/// A builder for [`DetectEntitiesOutput`](crate::operation::detect_entities::DetectEntitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectEntitiesOutputBuilder {
    pub(crate) entities: ::std::option::Option<::std::vec::Vec<crate::types::Entity>>,
    pub(crate) unmapped_attributes: ::std::option::Option<::std::vec::Vec<crate::types::UnmappedAttribute>>,
    pub(crate) pagination_token: ::std::option::Option<::std::string::String>,
    pub(crate) model_version: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DetectEntitiesOutputBuilder {
    /// Appends an item to `entities`.
    ///
    /// To override the contents of this collection use [`set_entities`](Self::set_entities).
    ///
    /// <p>The collection of medical entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn entities(mut self, input: crate::types::Entity) -> Self {
        let mut v = self.entities.unwrap_or_default();
        v.push(input);
        self.entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The collection of medical entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn set_entities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Entity>>) -> Self {
        self.entities = input;
        self
    }
    /// <p>The collection of medical entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn get_entities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Entity>> {
        &self.entities
    }
    /// Appends an item to `unmapped_attributes`.
    ///
    /// To override the contents of this collection use [`set_unmapped_attributes`](Self::set_unmapped_attributes).
    ///
    /// <p>Attributes extracted from the input text that we were unable to relate to an entity.</p>
    pub fn unmapped_attributes(mut self, input: crate::types::UnmappedAttribute) -> Self {
        let mut v = self.unmapped_attributes.unwrap_or_default();
        v.push(input);
        self.unmapped_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Attributes extracted from the input text that we were unable to relate to an entity.</p>
    pub fn set_unmapped_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnmappedAttribute>>) -> Self {
        self.unmapped_attributes = input;
        self
    }
    /// <p>Attributes extracted from the input text that we were unable to relate to an entity.</p>
    pub fn get_unmapped_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnmappedAttribute>> {
        &self.unmapped_attributes
    }
    /// <p>If the result of the previous request to <code>DetectEntities</code> was truncated, include the <code>PaginationToken</code> to fetch the next page of entities.</p>
    pub fn pagination_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pagination_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of the previous request to <code>DetectEntities</code> was truncated, include the <code>PaginationToken</code> to fetch the next page of entities.</p>
    pub fn set_pagination_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pagination_token = input;
        self
    }
    /// <p>If the result of the previous request to <code>DetectEntities</code> was truncated, include the <code>PaginationToken</code> to fetch the next page of entities.</p>
    pub fn get_pagination_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.pagination_token
    }
    /// <p>The version of the model used to analyze the documents. The version number looks like X.X.X. You can use this information to track the model used for a particular batch of documents.</p>
    /// This field is required.
    pub fn model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the model used to analyze the documents. The version number looks like X.X.X. You can use this information to track the model used for a particular batch of documents.</p>
    pub fn set_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version = input;
        self
    }
    /// <p>The version of the model used to analyze the documents. The version number looks like X.X.X. You can use this information to track the model used for a particular batch of documents.</p>
    pub fn get_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DetectEntitiesOutput`](crate::operation::detect_entities::DetectEntitiesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`entities`](crate::operation::detect_entities::builders::DetectEntitiesOutputBuilder::entities)
    /// - [`model_version`](crate::operation::detect_entities::builders::DetectEntitiesOutputBuilder::model_version)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::detect_entities::DetectEntitiesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::detect_entities::DetectEntitiesOutput {
            entities: self.entities.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entities",
                    "entities was not specified but it is required when building DetectEntitiesOutput",
                )
            })?,
            unmapped_attributes: self.unmapped_attributes,
            pagination_token: self.pagination_token,
            model_version: self.model_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "model_version",
                    "model_version was not specified but it is required when building DetectEntitiesOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
