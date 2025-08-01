// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferSnomedctOutput {
    /// <p>The collection of medical concept entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub entities: ::std::vec::Vec<crate::types::SnomedctEntity>,
    /// <p>If the result of the request is truncated, the pagination token can be used to fetch the next page of entities.</p>
    pub pagination_token: ::std::option::Option<::std::string::String>,
    /// <p>The version of the model used to analyze the documents, in the format n.n.n You can use this information to track the model used for a particular batch of documents.</p>
    pub model_version: ::std::option::Option<::std::string::String>,
    /// <p>The details of the SNOMED-CT revision, including the edition, language, and version date.</p>
    pub snomedct_details: ::std::option::Option<crate::types::SnomedctDetails>,
    /// <p>The number of characters in the input request documentation.</p>
    pub characters: ::std::option::Option<crate::types::Characters>,
    _request_id: Option<String>,
}
impl InferSnomedctOutput {
    /// <p>The collection of medical concept entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn entities(&self) -> &[crate::types::SnomedctEntity] {
        use std::ops::Deref;
        self.entities.deref()
    }
    /// <p>If the result of the request is truncated, the pagination token can be used to fetch the next page of entities.</p>
    pub fn pagination_token(&self) -> ::std::option::Option<&str> {
        self.pagination_token.as_deref()
    }
    /// <p>The version of the model used to analyze the documents, in the format n.n.n You can use this information to track the model used for a particular batch of documents.</p>
    pub fn model_version(&self) -> ::std::option::Option<&str> {
        self.model_version.as_deref()
    }
    /// <p>The details of the SNOMED-CT revision, including the edition, language, and version date.</p>
    pub fn snomedct_details(&self) -> ::std::option::Option<&crate::types::SnomedctDetails> {
        self.snomedct_details.as_ref()
    }
    /// <p>The number of characters in the input request documentation.</p>
    pub fn characters(&self) -> ::std::option::Option<&crate::types::Characters> {
        self.characters.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for InferSnomedctOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl InferSnomedctOutput {
    /// Creates a new builder-style object to manufacture [`InferSnomedctOutput`](crate::operation::infer_snomedct::InferSnomedctOutput).
    pub fn builder() -> crate::operation::infer_snomedct::builders::InferSnomedctOutputBuilder {
        crate::operation::infer_snomedct::builders::InferSnomedctOutputBuilder::default()
    }
}

/// A builder for [`InferSnomedctOutput`](crate::operation::infer_snomedct::InferSnomedctOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferSnomedctOutputBuilder {
    pub(crate) entities: ::std::option::Option<::std::vec::Vec<crate::types::SnomedctEntity>>,
    pub(crate) pagination_token: ::std::option::Option<::std::string::String>,
    pub(crate) model_version: ::std::option::Option<::std::string::String>,
    pub(crate) snomedct_details: ::std::option::Option<crate::types::SnomedctDetails>,
    pub(crate) characters: ::std::option::Option<crate::types::Characters>,
    _request_id: Option<String>,
}
impl InferSnomedctOutputBuilder {
    /// Appends an item to `entities`.
    ///
    /// To override the contents of this collection use [`set_entities`](Self::set_entities).
    ///
    /// <p>The collection of medical concept entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn entities(mut self, input: crate::types::SnomedctEntity) -> Self {
        let mut v = self.entities.unwrap_or_default();
        v.push(input);
        self.entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The collection of medical concept entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn set_entities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SnomedctEntity>>) -> Self {
        self.entities = input;
        self
    }
    /// <p>The collection of medical concept entities extracted from the input text and their associated information. For each entity, the response provides the entity text, the entity category, where the entity text begins and ends, and the level of confidence that Amazon Comprehend Medical has in the detection and analysis. Attributes and traits of the entity are also returned.</p>
    pub fn get_entities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SnomedctEntity>> {
        &self.entities
    }
    /// <p>If the result of the request is truncated, the pagination token can be used to fetch the next page of entities.</p>
    pub fn pagination_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pagination_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of the request is truncated, the pagination token can be used to fetch the next page of entities.</p>
    pub fn set_pagination_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pagination_token = input;
        self
    }
    /// <p>If the result of the request is truncated, the pagination token can be used to fetch the next page of entities.</p>
    pub fn get_pagination_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.pagination_token
    }
    /// <p>The version of the model used to analyze the documents, in the format n.n.n You can use this information to track the model used for a particular batch of documents.</p>
    pub fn model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the model used to analyze the documents, in the format n.n.n You can use this information to track the model used for a particular batch of documents.</p>
    pub fn set_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version = input;
        self
    }
    /// <p>The version of the model used to analyze the documents, in the format n.n.n You can use this information to track the model used for a particular batch of documents.</p>
    pub fn get_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version
    }
    /// <p>The details of the SNOMED-CT revision, including the edition, language, and version date.</p>
    pub fn snomedct_details(mut self, input: crate::types::SnomedctDetails) -> Self {
        self.snomedct_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the SNOMED-CT revision, including the edition, language, and version date.</p>
    pub fn set_snomedct_details(mut self, input: ::std::option::Option<crate::types::SnomedctDetails>) -> Self {
        self.snomedct_details = input;
        self
    }
    /// <p>The details of the SNOMED-CT revision, including the edition, language, and version date.</p>
    pub fn get_snomedct_details(&self) -> &::std::option::Option<crate::types::SnomedctDetails> {
        &self.snomedct_details
    }
    /// <p>The number of characters in the input request documentation.</p>
    pub fn characters(mut self, input: crate::types::Characters) -> Self {
        self.characters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of characters in the input request documentation.</p>
    pub fn set_characters(mut self, input: ::std::option::Option<crate::types::Characters>) -> Self {
        self.characters = input;
        self
    }
    /// <p>The number of characters in the input request documentation.</p>
    pub fn get_characters(&self) -> &::std::option::Option<crate::types::Characters> {
        &self.characters
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`InferSnomedctOutput`](crate::operation::infer_snomedct::InferSnomedctOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`entities`](crate::operation::infer_snomedct::builders::InferSnomedctOutputBuilder::entities)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::infer_snomedct::InferSnomedctOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::infer_snomedct::InferSnomedctOutput {
            entities: self.entities.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entities",
                    "entities was not specified but it is required when building InferSnomedctOutput",
                )
            })?,
            pagination_token: self.pagination_token,
            model_version: self.model_version,
            snomedct_details: self.snomedct_details,
            characters: self.characters,
            _request_id: self._request_id,
        })
    }
}
